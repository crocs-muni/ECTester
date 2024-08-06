{
  description = "ECTester";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    gradle2nix.url   = "github:tadfisher/gradle2nix/03c1b713ad139eb6dfc8d463b5bd348368125cf1";
    custom-nixpkgs.url = "github:quapka/nixpkgs/customPkgs";
  };

  outputs = { self, nixpkgs, custom-nixpkgs, flake-utils, gradle2nix, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        customPkgs = import custom-nixpkgs {
          inherit system overlays;
        };

        # removes the patch/revision from the version. E.g. getMajorMinor "1.2.3" = "1.2"
        getMajorMinor = version: builtins.concatStringsSep "." (pkgs.lib.take 2 ( builtins.splitVersion version));

        # Altered upstream packages
        boringssl = with pkgs; pkgs.boringssl.overrideAttrs (final: prev: rec {
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
        opensslBuilder = { version ? null, hash ? null }: (pkgs.openssl.override { static = true; }).overrideAttrs (final: prev: rec {
          pname = "openssl";
          src = if version != null then pkgs.fetchurl {
            url = "https://www.openssl.org/source/openssl-${version}.tar.gz";
            hash = hash;
          } else prev.src;
          # FIXME Removing patches might cause unwanted things; this should be version based!
          patches = [];
        });
        botan2Builder = { version, source_extension, hash }: pkgs.botan2.overrideAttrs (final: prev: {
          src = if ( version == null ) then prev.src else
            pkgs.fetchurl {
              urls = [
                 "http://botan.randombit.net/releases/Botan-${version}.${source_extension}"
              ];
              inherit hash;
            };
        });

        libgcryptBuilder = { version, hash }: pkgs.libgcrypt.overrideAttrs (final: prev: {
          configureFlags = ( prev.configureFlags or [] ) ++ [ "--enable-static" ];
          src = if version == null then prev.src else pkgs.fetchurl {
              url = "mirror://gnupg/libgcrypt/${prev.pname}-${version}.tar.bz2";
              inherit hash;
            };
        });
        libgpg-error = pkgs.libgpg-error.overrideAttrs (final: prev: {
          configureFlags = ( prev.configureFlags or [] ) ++ [ "--enable-static" ];
        });
        libtomcryptBuilder = { tcVersion, tcHash, tmVersion, tmHash }:
        (pkgs.libtomcrypt.override { libtommath = libtommathBuilder { version = tmVersion; hash = tmHash; }; }).overrideAttrs (final: prev: 
        let
          preBuilds = {
            "1.18" = ''
              makeFlagsArray+=(PREFIX=$out \
                CFLAGS="-DUSE_LTM -DLTM_DESC" \
                EXTRALIBS=\"-ltommath\" \
                INSTALL_GROUP=$(id -g) \
                INSTALL_USER=$(id -u))
            '';
            "1.17" = ''
              mkdir --parents $out/{lib, include, share/doc/}

              makeFlagsArray+=(PREFIX=$out \
                LIBPATH=$out/lib \
                INCPATH=$out/include \
                DATAPATH=$out/share/doc/libtomcrypt/pdf
                CFLAGS_OPTS="-DUSE_LTM -DLTM_DESC" \
                EXTRALIBS=\"-ltommath\" \
                GROUP=$(id -g) \
                USER=$(id -u))
            '';
            # "1.01" = ''
            # '';
          };
          preBuild = if tcVersion != null
          then if builtins.hasAttr (getMajorMinor tcVersion) preBuilds
            then preBuilds."${getMajorMinor tcVersion}"
            else preBuilds."1.17"
          else preBuilds."1.18";
        in
        rec {
          makefile = "makefile.unix";
          version = if tcVersion != null then tcVersion else prev.version;

          src = if version == prev.version then prev.src else pkgs.fetchFromGitHub {
            owner = "libtom";
            repo = "libtomcrypt";
            rev = if pkgs.lib.hasPrefix "1.18" version then "refs/tags/v${version}" else "refs/tags/${version}" ;
            hash = tcHash;
          };

          inherit preBuild;
          patches = if pkgs.lib.hasPrefix "1.18" version then ( prev.patches or [] ) ++ [
            # NOTE: LibTomCrypt does not expose the lib, when built statically (using `makefile and not `makefile.shared`).
            #       This patch copies the necessary code from `makefile.shared`.
            ./nix/libtomcrypt-pkgconfig-for-static.patch
            ] else [];
        });

        libtommathBuilder = { version, hash }: pkgs.libtommath.overrideAttrs (final: prev: rec {
          makefile = "makefile.unix";
          # version = if version != null then version else prev.version;
          version = "1.3.0";
          src = pkgs.fetchurl {
            url = "https://github.com/libtom/libtommath/releases/download/v${version}/ltm-${version}.tar.xz";
            # hash = if hash != null then hash else prev.hash;
            hash = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg";
          };
          patches = ( prev.patches or [] ) ++ [
            # NOTE: LibTomMath does not expose the lib, when built statically (using `makefile and not `makefile.shared`).
            #       This patch copies the necessary code from `makefile.shared`.
            ./nix/libtommath-pkgconfig-for-static-build.patch
          ];
        });
        nettle = pkgs.nettle.overrideAttrs (final: prev: {
          configureFlags = ( prev.configureFlags or [] ) ++ [ "--enable-static" ];
        });
        cryptoppBuilder = { version, hash }: (pkgs.cryptopp.override { enableStatic = true; }).overrideAttrs (final: prev: {
          src = if version == null then prev.src else
            pkgs.fetchFromGitHub {
              owner = "weidai11";
              repo = "cryptopp";
              rev = "CRYPTOPP_${version}";
              inherit hash;
          };
        });
        libressl = (pkgs.libressl.override { buildShared = false; } ).overrideAttrs (_old: rec {
          patches = [
            (pkgs.fetchpatch {
              url = "https://github.com/libressl/portable/commit/86e4965d7f20c3a6afc41d95590c9f6abb4fe788.patch";
              includes = [ "tests/tlstest.sh" ];
              hash = "sha256-XmmKTvP6+QaWxyGFCX6/gDfME9GqBWSx4X8RH8QbDXA=";
            })
          ];

          # NOTE: Due to name conflicts between OpenSSL and LibreSSL we need to resolve this manually.
          #       This is not needed for building the individual shims through Nix, as libresslShim build env does not
          #       contain OpenSSL at all, but for the interactive shell (started with `nix develop`), when multiple
          #       lib shims are built alongside each other.
          postFixup = pkgs.lib.concatLines [
            ( _old.postFixup or "" )
            ''
            cp $dev/lib/pkgconfig/libcrypto.pc $dev/lib/pkgconfig/libresslcrypto.pc
            sed --in-place --expression 's/-lcrypto/-lresslcrypto/' $dev/lib/pkgconfig/libresslcrypto.pc
            ln -s $out/lib/libcrypto.so $out/lib/libresslcrypto.so
            ln -s $out/lib/libcrypto.a $out/lib/libresslcrypto.a
            ''
          ];

        });
        gmp = pkgs.gmp.override { withStatic = true; };

        # Custom added packages
        wolfcryptjni = with customPkgs; wolfcrypt-jni.overrideAttrs (final: prev: {
          src = pkgs.fetchFromGitHub {
            owner = "wolfSSL";
            repo = "wolfcrypt-jni";
            rev = "0497ee767c994775beda2f2091009593961e5c7e";
            hash = "sha256-mtUXUyIKJ617WzAWjlOaMscWM7zuGBISVMEAbmQNBOg=";
          };
        });

        # Shims and libs
        # Current list of targets: tomcrypt botan cryptopp openssl boringssl gcrypt mbedtls ippcp nettle libressl
        tomcryptShimBuilder = { tcVersion, tcHash, tmVersion, tmHash}: pkgs.callPackage ./nix/tomcryptshim.nix {
          inherit pkgs;
          libtomcrypt = ( libtomcryptBuilder { inherit tcVersion tcHash tmVersion tmHash; });
          libtommath = ( libtommathBuilder { version = tmVersion; hash = tmHash; });
        };
        botanShimBuilder = { version, source_extension, hash }: pkgs.callPackage ./nix/botanshim.nix { botan2 = botan2Builder { inherit version source_extension hash; }; };
        cryptoppShimBuilder = { version, hash}: pkgs.callPackage ./nix/cryptoppshim.nix { cryptopp = cryptoppBuilder { inherit version hash; };};
        opensslShimBuilder = { version, hash }: import ./nix/opensslshim.nix { inherit pkgs; openssl = (opensslBuilder { version = version; hash = hash;}); };
        boringsslShim = import ./nix/boringsslshim.nix { inherit pkgs; boringssl = boringssl; };
        gcryptShimBuilder = { version, hash}: import ./nix/gcryptshim.nix { inherit pkgs libgpg-error; libgcrypt = libgcryptBuilder { inherit version hash; }; };
        mbedtlsShim = import ./nix/mbedtlsshim.nix { pkgs = pkgs; };
        ippcpShim = import ./nix/ippcpshim.nix { pkgs = pkgs; ipp-crypto = customPkgs.ipp-crypto; };
        nettleShim = import ./nix/nettleshim.nix { inherit pkgs nettle gmp; };
        libresslShim = import ./nix/libresslshim.nix { inherit pkgs libressl; };

        commonLibs = import ./nix/commonlibs.nix { pkgs = pkgs; };

        buildECTesterStandalone = {
          tomcrypt ? { version = null; hash = null; },
          tommath ? { version = null; hash = null; },
          botan ? { version = null; source_extension = null; hash = null; },
          cryptopp ? { version = null; hash = null; },
          openssl ? { version = null; hash = null; },
          boringssl ? { version = null; hash = null; },
          gcrypt ? { version = null; hash = null; },
        }: (
          let
            tomcryptShim = tomcryptShimBuilder {
              tcVersion = tomcrypt.version;
              tcHash = tomcrypt.hash;
              tmVersion = tommath.version;
              tmHash = tommath.hash;
            };
            opensslShim = (opensslShimBuilder { inherit (openssl) version hash; });
            botanShim = botanShimBuilder { inherit (botan) version source_extension hash; };
            cryptoppShim = cryptoppShimBuilder { inherit (cryptopp) version hash; };
            gcryptShim = gcryptShimBuilder { inherit (gcrypt) version hash; };
          in
          with pkgs;
            gradle2nix.builders.${system}.buildGradlePackage rec {
              pname = "ECTesterStandalone";
              version = "0.3.3";
              lockFile = ./gradle.lock;

              # NOTE: the shims are built separately, therefore no need to call build `libs` target
              gradleBuildFlags = [ ":standalone:uberJar"];
              src = ./.;

              jniLibsPath = "standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/";

              preConfigure = ''
                cp ${tomcryptShim.out}/lib/tomcrypt_provider.so ${jniLibsPath}
                cp ${botanShim.out}/lib/botan_provider.so ${jniLibsPath}
                cp ${cryptoppShim.out}/lib/cryptopp_provider.so ${jniLibsPath}
                cp ${opensslShim.out}/lib/openssl_provider.so ${jniLibsPath}
                cp ${boringsslShim.out}/lib/boringssl_provider.so ${jniLibsPath}
                cp ${gcryptShim.out}/lib/gcrypt_provider.so ${jniLibsPath}
                cp ${mbedtlsShim.out}/lib/mbedtls_provider.so ${jniLibsPath}
                cp ${ippcpShim.out}/lib/ippcp_provider.so ${jniLibsPath}
                cp ${nettleShim.out}/lib/nettle_provider.so ${jniLibsPath}
                cp ${libresslShim.out}/lib/libressl_provider.so ${jniLibsPath}
                cp ${wolfcryptjni}/lib/* ${jniLibsPath}
                cp ${commonLibs}/lib/* ${jniLibsPath}
              '';

              nativeBuildInputs = [ makeWrapper ];

              LD_LIBRARY_PATH = lib.makeLibraryPath [ wolfcryptjni ];

              WOLFCRYPT_LIB_PATH = "${wolfcryptjni}/lib";

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
        packages = rec {
          default = openssl.v331;
          tomcrypt = pkgs.callPackage ./nix/tomcrypt_pkg_versions.nix { inherit buildECTesterStandalone; };
          botan = pkgs.callPackage ./nix/botan_pkg_versions.nix { inherit buildECTesterStandalone; };
          cryptopp = pkgs.callPackage ./nix/cryptopp_pkg_versions.nix { inherit buildECTesterStandalone; };
          openssl = pkgs.callPackage ./nix/openssl_pkg_versions.nix { inherit buildECTesterStandalone; };
          boringssl = pkgs.callPackage ./nix/boringssl_pkg_versions.nix { inherit buildECTesterStandalone; };
          gcrypt = pkgs.callPackage ./nix/gcrypt_pkg_versions.nix { inherit buildECTesterStandalone; };

          fetchReleases = with pkgs.python3Packages; buildPythonApplication {
            pname = "fetchReleases";
            version = "0.1.0";
            format = "other";

            propagatedBuildInputs = [
              jinja2
              requests
              beautifulsoup4
            ];

            src = ./fetchReleases.py;
            dontUnpack = true;
            installPhase = ''
              install -Dm755 $src $out/bin/$pname
            '';

          };

        };
        devShells.default = with pkgs; mkShell rec {
          nativeBuildInputs = [
            pkg-config
          ];

          preConfigure = ''
            cp ${boringssl}/lib/lib_boringssl.a standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/
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
            (opensslBuilder {})
            libressl
            # glibc
            boringssl
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
            (opensslBuilder {})
            boringssl
            libgcrypt
            libgpg-error
            nettle
            gmp
            libgpg-error
            libconfig
            wolfcryptjni
          ];

          BORINGSSL_CFLAGS = "${boringssl.dev.outPath}/include";
          WOLFCRYPT_LIB_PATH = "${wolfcryptjni}/lib";


        IPP_CRYPTO_HEADER = "${customPkgs.ipp-crypto.dev}/include";
        IPP_CRYPTO_LIB = "${customPkgs.ipp-crypto}/lib/";


        };
      }
    );
}
