{
  description = "ECTester";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    gradle2nix.url   = "github:tadfisher/gradle2nix/03c1b713ad139eb6dfc8d463b5bd348368125cf1";
    custom-nixpkgs.url = "github:quapka/nixpkgs/customPkgs"; # custom for of nixpkgs with ipp-crypto packaged
    # FIXME how to add submodule declaratively?
    # submodule = {
    #   url = ./
    # };
  };

  outputs = { self, nixpkgs, custom-nixpkgs, flake-utils, gradle2nix, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        commonLibs = import ./nix/commonlibs.nix { pkgs = pkgs; };
        wolfcryptjni = with customPkgs; wolfcrypt-jni.overrideAttrs (final: prev: {
          src = pkgs.fetchFromGitHub {
            owner = "wolfSSL";
            repo = "wolfcrypt-jni";
            rev = "0497ee767c994775beda2f2091009593961e5c7e";
            hash = "sha256-mtUXUyIKJ617WzAWjlOaMscWM7zuGBISVMEAbmQNBOg=";
          };
        });
        patched_boringssl = with pkgs; pkgs.boringssl.overrideAttrs (final: prev: rec {
           src = fetchgit {
            url = "https://boringssl.googlesource.com/boringssl";
            rev = "67422ed4434116daa8898773692165ddd51a6ac2";
            hash = "sha256-7ScEX6ZqBl3PL+zn4bBBPFu5xxP1YswGQxh7g8+9VUc=";
          };

          # NOTE this build does not match upstream, but is what ECTester did at the time of writing
          buildPhase = ''
            cmake -GNinja -Bbuild
            pushd build
            ninja crypto
            popd
          '';

          installPhase = ''
            mkdir --parents $bin/bin $dev $out/lib
            mv include $dev

            pushd build
            mv crypto/libcrypto.a $out/lib/lib_boringssl.a
            popd
          '';
        });
        # FIXME: `nix develeop` now has different version than `nix run`
        openssl = { version ? "", hash ? "" }: (pkgs.openssl.override { static = true; }).overrideAttrs (final: prev: rec {
          pname = "openssl";
          src = if version != "" then pkgs.fetchurl {
            url = "https://www.openssl.org/source/openssl-${version}.tar.gz";
            hash = hash;
          } else prev.src;
          # FIXME Removing patches might cause unwanted things; this should be version based!
          patches = [];
        });
        libgcrypt = pkgs.libgcrypt.overrideAttrs (final: prev: {
          configureFlags = ( prev.configureFlags or [] ) ++ [ "--enable-static" ];
        });
        libgpg-error = pkgs.libgpg-error.overrideAttrs (final: prev: {
          configureFlags = ( prev.configureFlags or [] ) ++ [ "--enable-static" ];
        });
        libtomcrypt = (pkgs.libtomcrypt.override { libtommath = libtommath; }).overrideAttrs (final: prev: {
          makefile = "makefile.unix";
        });
        libtommath = pkgs.libtommath.overrideAttrs (final: prev: rec {
          makefile = "makefile.unix";
          version = "1.3.0";
          src = pkgs.fetchurl {
            url = "https://github.com/libtom/libtommath/releases/download/v${version}/ltm-${version}.tar.xz";
            sha256 = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg=";
          };
        });
        nettle = pkgs.nettle.overrideAttrs (final: prev: {
          configureFlags = ( prev.configureFlags or [] ) ++ [ "--enable-static" ];
        });
        cryptopp = pkgs.cryptopp.override { enableStatic = true; };
        libressl = (pkgs.libressl.override { buildShared = false; } ).overrideAttrs (_old: rec {
          # devLibPath = pkgs.lib.makeLibraryPath [ pkgs.libressl.dev ];
          # pname = "libressl";
          # version = "3.9.2";
          # includes = [ "tests/tlstest.sh" ];
          # src = pkgs.fetchurl {
          #   url = "mirror://openbsd/LibreSSL/${pname}-${version}.tar.gz";
          #   hash = "sha256-ewMdrGSlnrbuMwT3/7ddrTOrjJ0nnIR/ksifuEYGj5c=";
          # };
          # nativeBuildInputs = _old.nativeBuildInputs ++ (with pkgs; [
          #   pkg-config
          # ]);

          # Patched according to the previous versions:
          # https://github.com/NixOS/nixpkgs/blob/nixos-24.05/pkgs/development/libraries/libressl/default.nix#L118
          # For unknown reasons the newer versions are not patched this way (yet?)
          patches = [
            (pkgs.fetchpatch {
              url = "https://github.com/libressl/portable/commit/86e4965d7f20c3a6afc41d95590c9f6abb4fe788.patch";
              includes = [ "tests/tlstest.sh" ];
              hash = "sha256-XmmKTvP6+QaWxyGFCX6/gDfME9GqBWSx4X8RH8QbDXA=";
            })
          ];

          # NOTE: Due to name conflicts between OpenSSL and LibreSSL we need to resolve this manually.
          postFixup =  pkgs.lib.concatLines [ 
            ( _old.postFixup or "" )
            ''
            cp $dev/lib/pkgconfig/libcrypto.pc $dev/lib/pkgconfig/libresslcrypto.pc
            sed --in-place --expression 's/-lcrypto/-lresslcrypto/' $dev/lib/pkgconfig/libresslcrypto.pc
            ln -s $out/lib/libcrypto.so $out/lib/libresslcrypto.so
            ln -s $out/lib/libcrypto.a $out/lib/libresslcrypto.a
            ''
          ];

        });
        libresslShim = import ./nix/libresslshim.nix { pkgs = pkgs; libressl = libressl; };
        # Current list of targets: tomcrypt botan cryptopp openssl boringssl gcrypt mbedtls ippcp nettle libressl
        tomcryptShim = import ./nix/tomcryptshim.nix { inherit pkgs libtomcrypt libtommath; };
        botanShim = import ./nix/botanshim.nix { inherit pkgs; };
        cryptoppShim = import ./nix/cryptoppshim.nix { inherit pkgs cryptopp; };
        opensslShimBuilder = { version, hash }: import ./nix/opensslshim.nix { inherit pkgs; openssl = (openssl { version = version; hash = hash;}); };
        boringsslShim = import ./nix/boringsslshim.nix { inherit pkgs; boringssl = patched_boringssl; };
        mbedtlsShim = import ./nix/mbedtlsshim.nix { pkgs = pkgs; };
        ippcryptoShim = import ./nix/ippcryptoshim.nix { pkgs = pkgs; ipp-crypto = customPkgs.ipp-crypto; };

        overlays = [];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        customPkgs = import custom-nixpkgs {
          inherit system overlays;
        };
        buildECTesterStandalone = { opensslVersion, opensslHash }: (
          let
            opensslShim = (opensslShimBuilder { version = opensslVersion; hash = opensslHash; });
          in
          with pkgs;
            gradle2nix.builders.${system}.buildGradlePackage rec {
              pname = "ECTesterStandalone";
              version = "0.3.3";
              # gradleInstallFlags = [ "installDist" ];
              # gradleBuildFlags = [ "standalone:uberJar" ]; # ":standalone:compileJava" ":standalone:uberJar" ]; "--no-build-cache"
              lockFile = ./gradle.lock;
              # FIXME all libs need to be built, but combining Gradle build all-libs and dedicated shim derivations won't work 
              gradleBuildFlags = [ "libs" "-PlibName=tomcrypt" ":standalone:uberJar"]; # ":standalone:compileJava" ":standalone:uberJar" ]; "--no-build-cache"
              src = ./.;

              jniLibsPath = "standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/";

              preConfigure = ''
                cp ${boringsslShim.out}/lib/boringssl_provider.so standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/
                cp ${tomcryptShim.out}/lib/tomcrypt_provider.so ${jniLibsPath}
                cp ${botanShim.out}/lib/botan_provider.so ${jniLibsPath}
                cp ${cryptoppShim.out}/lib/cryptopp_provider.so ${jniLibsPath}
                cp ${opensslShim.out}/lib/openssl_provider.so ${jniLibsPath}
                cp ${boringsslShim.out}/lib/boringssl_provider.so ${jniLibsPath}
                cp ${commonLibs}/lib/* ${jniLibsPath}
              '';

              nativeBuildInputs = [
                # libresslShim
                gdb
                ant
                jdk17
                pkg-config
                global-platform-pro
                gradle
                makeWrapper

                # libraries to test
                # patched_boringssl
                # libressl
                libtomcrypt
                libtommath
                botan2
                cryptopp

                # libraries' dependencies
                # cmake
                # ninja
                gawk
                automake
                go
                gtest
                libunwind
                autoconf
                libb64

                clang
                libgcrypt
                libgpg-error
                mbedtls
                nasm
                libtool
                perl

                wolfssl
                nettle

                gmp
                libgpg-error
                wget
                libconfig
              ];

              buildInputs = [
                jdk17_headless
                # libressl
                commonLibs
              ];

              LD_LIBRARY_PATH = lib.makeLibraryPath [
                libtommath
                libtomcrypt
                botan2
                cryptopp
                libgcrypt
                libgpg-error
                # libressl
                # patched_boringssl
                ninja
                nettle
                gmp
                libgpg-error
                libconfig
                wolfcryptjni
                commonLibs
              ];

              # BORINGSSL_CFLAGS = "${patched_boringssl.dev.outPath}/include";
              WOLFCRYPT_LIB_PATH = "${wolfcryptjni}/lib";

              # FIXME more things to copy here
              installPhase = ''
                mkdir -p $out
                cp -r standalone/build $out
              '';

              postFixup = ''
                makeWrapper \
                  ${jdk17_headless}/bin/java $out/bin/${pname} \
                  --add-flags "-jar $out/build/libs/${pname}.jar" \
                  --set LD_LIBRARY_PATH ${LD_LIBRARY_PATH}:$LD_LIBRARY_PATH
              '';

        });
      in
      {
        packages = {
          default = buildECTesterStandalone {
            opensslVersion="3.3.1"; opensslHash="sha256-d3zVlihMiDN1oqehG/XSeG/FQTJV76sgxQ1v/m0CC34=";
          };
          openssl_331 = buildECTesterStandalone {
            opensslVersion="3.3.1"; opensslHash="sha256-d3zVlihMiDN1oqehG/XSeG/FQTJV76sgxQ1v/m0CC34=";
          }; 
          openssl_322 = buildECTesterStandalone {
            opensslVersion="3.2.2"; opensslHash="sha256-GXFJwY2enyksQ/BACsq6EuX1LKz+BQ89GZJ36nOOwuc=";
          }; 
          openssl_316 = buildECTesterStandalone {
            opensslVersion="3.1.6"; opensslHash="sha256-XSvkA2tHjvPLCoVMqbNTByw6DibYpW+PCrn7btMtONc=";
          }; 
          openssl_3014 = buildECTesterStandalone {
            opensslVersion="3.0.14"; opensslHash="sha256-7soDXU3U6E/CWEbZUtpil0hK+gZQpvhMaC453zpBI8o=";
          }; 
          # openssl_111w = buildECTesterStandalone "1.1.1w" "sha256-zzCYlQy02FOtlcCEHx+cbT3BAtzPys1SHZOSUgi3asg=";
        };
        devShells.default = with pkgs; mkShell rec {
          nativeBuildInputs = [
            pkg-config
          ];

          preConfigure = ''
            cp ${patched_boringssl}/lib/lib_boringssl.a standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/
          '';

          buildInputs = [
            # # gradle2nix
            # libresslShim
            gdb
            ant
            jdk17
            pkg-config
            global-platform-pro
            gradle
            # libraries to test
            (openssl {})
            libressl
            # glibc
            patched_boringssl
            libtomcrypt
            libtommath
            botan2
            cryptopp

            # libraries' dependencies
            cmake
            ninja
            gawk
            automake
            go
            gtest
            libunwind
            autoconf
            libb64

            # clang
            libgcrypt
            libgpg-error
            mbedtls
            nasm
            libtool
            perl

            wolfssl
            nettle
            # libressl

            customPkgs.ipp-crypto

            gmp
            libgpg-error
            wget
            libconfig
          ];

          LD_LIBRARY_PATH = with pkgs; pkgs.lib.makeLibraryPath [
            libtommath
            libtomcrypt
            botan2
            cryptopp
            # (openssl {})
            (openssl {})
            patched_boringssl
            libgcrypt
            libgpg-error
            nettle
            gmp
            libgpg-error
            libconfig
            wolfcryptjni
          ];

          BORINGSSL_CFLAGS = "${patched_boringssl.dev.outPath}/include";
          WOLFCRYPT_LIB_PATH = "${wolfcryptjni}/lib";


        IPP_CRYPTO_HEADER = "${customPkgs.ipp-crypto.dev}/include";
        IPP_CRYPTO_LIB = "${customPkgs.ipp-crypto}/lib/";


        };
      }
    );
}
