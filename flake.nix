{
  description = "ECTester";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    gradle2nix.url   = "github:tadfisher/gradle2nix/03c1b713ad139eb6dfc8d463b5bd348368125cf1";
    # FIXME how to add submodule declaratively?
    # submodule = {
    #   url = ./
    # };
  };

  outputs = { self, nixpkgs, flake-utils, gradle2nix, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        libresslShim = with pkgs; stdenv.mkDerivation {
          name = "LibreSSLShim";
          src = ./standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

          buildInputs = [
            libressl
            pkg-config
            jdk11_headless
          ];

          buildPhase = ''
            make libressl
          '';

          installPhase = ''
            mkdir --parents $out/lib
            cp libressl_provider.so $out/lib
          '';
        };
        # openssl_3013 = pkgs.openssl.overrideAttrs (_old: rec {
        #   version = "3.0.13";
        #   pname = "openssl";
        #   src = pkgs.fetchurl {
        #     url = "https://www.openssl.org/source/openssl-${version}.tar.gz";
        #     hash = "sha256-iFJXU/edO+wn0vp8ZqoLkrOqlJja/ZPXz6SzeAza4xM=";
        #   };
        #   # FIXME this might cause unwanted things
        #   patches = [];
        # });
        # openssl_315 = pkgs.openssl.overrideAttrs (_old: rec {
        #   version = "3.1.5";
        #   pname = "openssl";
        #   src = pkgs.fetchurl {
        #     url = "https://www.openssl.org/source/openssl-${version}.tar.gz";
        #     hash = "sha256-auAVRn2r8EabE5rakzGTJ74kuYJR/67O2gIhhI3AkmI=";
        #   };
        #   # FIXME this might cause unwanted things
        #   patches = [];
        # });
        boirngssl = pkgs.boringssl.overrideAttrs (_old: rec {
          postFixup = ''
            ls 
          '';
        });
        libressl = pkgs.libressl.overrideAttrs (_old: rec {
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
            _old.postFixup
            ''
            cp $dev/lib/pkgconfig/libcrypto.pc $dev/lib/pkgconfig/libresslcrypto.pc
            sed --in-place --expression 's/-lcrypto/-lresslcrypto/' $dev/lib/pkgconfig/libresslcrypto.pc
            ln -s $out/lib/libcrypto.so $out/lib/libresslcrypto.so
            ''
          ];

        });
        overlays = [
          # (final: prev: {
          #   openssl_01 = prev.openssl.overrideAttrs (old: rec{
          #     version = "3.0.8";
          #     pname = "openssl";
          #     src = pkgs.fetchurl {
          #       url = "https://www.openssl.org/source/openssl-${version}.tar.gz";
          #       hash = "sha256-bBPSvzj98x6sPOKjRwc2c/XWMmM5jx9p0N9KQSU+Sz4=";
          #     };
          #     FIXME Removing patches might cause unwanted things.
          #     patches = [];
          #   });
          # })
        ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        buildECTesterStandalone = { opensslVersion, opensslHash }: (
          let
            patched_openssl = pkgs.openssl.overrideAttrs (_old: rec {
              version = opensslVersion;
              pname = "openssl";
              src = pkgs.fetchurl {
                url = "https://www.openssl.org/source/openssl-${version}.tar.gz";
                hash = opensslHash;
              };
              # FIXME Removing patches might cause unwanted things.
              patches = [];
            });

            # devLibPath = pkgs.lib.makeLibraryPath [ pkgs.libressl.dev ];
            # libressl = pkgs.libressl.overrideAttrs (_old: {
            #   fixupPhase = ''
            #     cp ${devLibPath}/openssl.pc ${devLibPath}/libressl.pc
            #   '';
            # });
          in
          with pkgs;
            gradle2nix.builders.${system}.buildGradlePackage rec {
              pname = "ECTesterStandalone";
              version = "0.3.3";
              # gradleInstallFlags = [ "installDist" ];
              # gradleBuildFlags = [ "standalone:uberJar" ]; # ":standalone:compileJava" ":standalone:uberJar" ]; "--no-build-cache"
              lockFile = ./gradle.lock;
              gradleBuildFlags = [ ":standalone:uberJar"]; # ":standalone:compileJava" ":standalone:uberJar" ]; "--no-build-cache"
              src = ./.;

              preConfigure = ''
                cp ${libresslShim.out}/lib/libressl_provider.so standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/
                pushd standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/
                make lib_timing.so lib_csignals.so lib_cppsignals.so
                popd
              '';

              nativeBuildInputs = [
                # libresslShim
                gdb
                ant
                jdk17
                pkg-config
                global-platform-pro
                gradle
                # patched_openssl
                makeWrapper

                # libraries to test
                # openssl_3013
                # boringssl
                libressl
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

              # buildBoringSSL = ''
              #   pushd ext/boringssl
              #   mkdir --parents build
              #   pushd build
              #   cmake -GNinja -DBUILD_SHARED_LIBS=1 ..
              #   ninja
              #   popd
              # '';

              # buildLibreSSL = ''
              #   pushd ext/libressl
              #   ./autogen.sh
              #   mkdir --parents build
              #   pushd build
              #   cmake -GNinja -DBUILD_SHARED_LIBS=1 ..
              #   ninja
              #   popd
              # '';

              # TODO OpenJDK 64-Bit Server VM warning: You have loaded library
              # /home/qup/.local/share/ECTesterStandalone/lib/lib_ippcp.so which
              # might have disabled stack guard. The VM will try to fix the stack
              # guard now. It's highly recommended that you fix the library with
              # 'execstack -c <libfile>', or link it with '-z noexecstack'.
              # buildIppCrypto = ''
              #   pushd ext/ipp-crypto
              #   CC=clang CXX=clang++ cmake CMakeLists.txt -GNinja -Bbuild -DARCH=intel64  # Does not work with GCC 12+
              #   mkdir --parents build
              #   pushd build
              #   ninja
              #   popd
              #  '';

              # buildMbedTLS = ''
              #   pushd ext/mbedtls
              #   python -m venv virt
              #   . virt/bin/activate
              #   pip install -r scripts/basic.requirements.txt
              #   cmake -GNinja -Bbuild -DUSE_SHARED_MBEDTLS_LIBRARY=On
              #   cd build
              #   ninja
              # '';

              # wolfCrypt-JNI = ''
              #   pushd ext/wolfcrypt-jni
              #   mkdir junit
              #   wget -P junit/ https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar
              #   wget -P junit/ https://repo1.maven.org/maven2/org/hamcrest/hamcrest-all/1.3/hamcrest-all-1.3.jar
              #   make -f makefile.linux
              #   env JUNIT_HOME=junit/ ant build-jce-release
              # '';

              # preConfigure = lib.concatLines [
              #   buildBoringSSL
              #   buildLibreSSL
              #   buildIppCrypto
              #   buildMbedTLS
              #   wolfCrypt-JNI
              # ];

              # buildPhase = ''
              #   ./gradlew clean build --offline
              # '';

              buildInputs = [
                jdk17_headless
                libressl
                # patched_openssl
              ];

              LD_LIBRARY_PATH = lib.makeLibraryPath [
                # libresslShim

                libtommath
                libtomcrypt
                botan2
                cryptopp
                libgcrypt
                patched_openssl
                libressl
                ninja
                nettle
                gmp
                libgpg-error
                libconfig
              ];

              # FIXME more things to copy here
              installPhase = ''
                mkdir -p $out
                cp -r standalone/build $out
                echo ${opensslVersion} > $out/build/opensslVersion
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
            libresslShim
          ];

          preConfigure = ''
            cp ${libresslShim.out}/libressl_provider.so standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/
            ls standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni
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
            # openssl
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
            mbedtls
            nasm
            libtool
            perl

            wolfssl
            nettle
            # libressl

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
            # openssl
            libgcrypt
            nettle
            gmp
            libgpg-error
            libconfig
          ];

          # NOTE: Mixing postVenvCreation aznd shellHook results in only shellHook being called
          # shellHook = ''
          #   source ${venvDir}/bin/activate
          #   export PATH=$PATH:$HOME/projects/ts-spect-compiler/build/src/apps;
          #   export TS_REPO_ROOT=`pwd`;
          # '';

        # NIX_CFLAGS_COMPILE="";

        buildBoringSSL = ''
          mkdir --parents build
          pushd build
          cmake -GNinja -DBUILD_SHARED_LIBS=1 ..
          ninja
          popd
        '';

        buildLibreSSL = ''
          ./autogen.sh
          mkdir --parents build
          pushd build
          cmake -GNinja -DBUILD_SHARED_LIBS=1 ..
          ninja
          popd
        '';

        # TODO OpenJDK 64-Bit Server VM warning: You have loaded library
        # /home/qup/.local/share/ECTesterStandalone/lib/lib_ippcp.so which
        # might have disabled stack guard. The VM will try to fix the stack
        # guard now. It's highly recommended that you fix the library with
        # 'execstack -c <libfile>', or link it with '-z noexecstack'.
        buildIppCrypto = ''
          CC=clang CXX=clang++ cmake CMakeLists.txt -GNinja -Bbuild -DARCH=intel64  # Does not work with GCC 12+
          mkdir --parents build
          pushd build
          ninja
          popd
         '';

         buildMbedTLS = ''
           python -m venv virt
           . virt/bin/activate
           pip install -r scripts/basic.requirements.txt
           cmake -GNinja -Bbuild -DUSE_SHARED_MBEDTLS_LIBRARY=On
           cd build
           ninja
         '';

         wolfCrypt-JNI = ''
           mkdir junit
           wget -P junit/ https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar
           wget -P junit/ https://repo1.maven.org/maven2/org/hamcrest/hamcrest-all/1.3/hamcrest-all-1.3.jar
           make -f makefile.linux
           env JUNIT_HOME=junit/ ant build-jce-release
         '';

        # TODO add LD_LIB properly
        # shellHook = ''
        #   export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$HOME/projects/ts-spect-compiler/build/src/cosim
        #   NIX_CFLAGS_COMPILE=
        # '';

          # pushd ext/wolfcrypt-jni
          # ${wolfCrypt-JNI}
          # popd

        #   pushd ext/mbedtls
        #   ${buildMbedTLS}
        #   popd
        # '';
        #   git submodule update --init --recursive

        #   pushd ext/boringssl
        #   ${buildBoringSSL}
        #   popd

        #   pushd ext/ipp-crypto
        #   ${buildIppCrypto}
        #   popd

        #   pushd ext/libressl
        #   ${buildLibreSSL}
        #   popd
        # '';

        };
      }
    );
}
