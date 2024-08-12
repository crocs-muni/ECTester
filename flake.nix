{
  description = "ECTester";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gradle2nix.url = "github:tadfisher/gradle2nix/03c1b713ad139eb6dfc8d463b5bd348368125cf1";
    custom-nixpkgs.url = "github:quapka/nixpkgs/customPkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      custom-nixpkgs,
      flake-utils,
      gradle2nix,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ ];
        pkgs = import nixpkgs { inherit system overlays; };
        customPkgs = import custom-nixpkgs { inherit system overlays; };

        # removes the patch/revision from the version. E.g. getMajorMinor "1.2.3" = "1.2"
        getMajorMinor =
          version: builtins.concatStringsSep "." (pkgs.lib.take 2 (builtins.splitVersion version));

        # Altered upstream packages
        boringsslBuilder =
          {
            rev ? null,
            hash ? null,
          }:
          pkgs.boringssl.overrideAttrs (
            final: prev: rec {
              version = if rev != null then rev else prev.version;
              src =
                if rev == null then
                  prev.src
                else
                  pkgs.fetchgit {
                    url = "https://boringssl.googlesource.com/boringssl";
                    inherit rev hash;
                  };
              postFixup = ''
                cp $out/lib/libcrypto.a $out/lib/lib_boringssl.a
              '';
            }
          );
        # FIXME: `nix develeop` now has different version than `nix run`
        opensslBuilder =
          {
            version ? null,
            hash ? null,
          }:
          if version == null then
            (pkgs.openssl.override { static = true; })
          else
            (pkgs.openssl.override { static = true; }).overrideAttrs (
              final: prev: rec {
                inherit version;
                src = pkgs.fetchurl {
                  url = "https://www.openssl.org/source/openssl-${version}.tar.gz";
                  inherit hash;
                };
                # FIXME Removing patches might cause unwanted things; this should be version based!
                patches = [ ];
              }
            );
        botan2Builder =
          {
            version ? null,
            source_extension ? null,
            hash ? null,
          }:
          if version == null then
            pkgs.botan2
          else
            pkgs.botan2.overrideAttrs (
              final: prev: {
                inherit version;
                src = pkgs.fetchurl {
                  urls = [ "http://botan.randombit.net/releases/Botan-${version}.${source_extension}" ];
                  inherit hash;
                };
                patches =
                	{ "2.0.0" = ./nix/botan-2.0.0-2.0.1.patch;
                	  "2.0.1" = ./nix/botan-2.0.0-2.0.1.patch;
                	  "2.2.0" = [./nix/botan-fe25519-stdexcept.patch ];
                	  "2.3.0" = [./nix/botan-fe25519-stdexcept.patch ./nix/botan-types-stdexcept.patch];
                	  "2.4.0" = [./nix/botan-fe25519-stdexcept.patch ./nix/botan-types-stdexcept.patch];
                	  "2.5.0" = [./nix/botan-fe25519-stdexcept.patch ./nix/botan-types-stdexcept.patch];
                	  "2.6.0" = [./nix/botan-fe25519-stdexcept.patch ./nix/botan-types-stdexcept.patch];
                	  "2.7.0" = [./nix/botan-fe25519-stdexcept.patch ./nix/botan-types-stdexcept.patch];
                	  "2.8.0" = [./nix/botan-fe25519-stdexcept.patch ./nix/botan-types-stdexcept.patch];}."${version}" or (prev.patches or [ ]);
                patchFlags = ["-p1" "-r-"];
              }
            );

        # FIXME we need to build also the correct version of libgpg-error - which is what?
        libgcryptBuilder =
          {
            version ? null,
            hash ? null,
          }:
          if version == null then
            pkgs.libgcrypt.overrideAttrs (
              final: prev: { configureFlags = (prev.configureFlags or [ ]) ++ [ "--enable-static" ]; }
            )
          else
            pkgs.libgcrypt.overrideAttrs (
              final: prev: {
                inherit version;
                configureFlags = (prev.configureFlags or [ ]) ++ [ "--enable-static" ];
                src = pkgs.fetchurl {
                  url = "mirror://gnupg/libgcrypt/${prev.pname}-${version}.tar.bz2";
                  inherit hash;
                };
              }
            );
        libgpg-error = pkgs.libgpg-error.overrideAttrs (
          final: prev: { configureFlags = (prev.configureFlags or [ ]) ++ [ "--enable-static" ]; }
        );

        mbedtlsBuilder =
          {
            version ? null,
            hash ? null,
          }:
          if version == null then
            pkgs.mbedtls
          else
            pkgs.mbedtls.overrideAttrs (
              final: prev: {
                inherit version;
                src = pkgs.fetchFromGitHub {
                  owner = "Mbed-TLS";
                  repo = "mbedtls";
                  rev = "mbedtls-${version}";
                  inherit hash;
                  # mbedtls >= 3.6.0 uses git submodules
                  fetchSubmodules = true;
                };
              }
            );

        ipp-cryptoBuilder =
          {
            version ? null,
            hash ? null,
          }:
          if version == null then
            customPkgs.ipp-crypto
          else
            customPkgs.ipp-crypto.overrideAttrs (
              final: prev: {
                inherit version;
                src = pkgs.fetchFromGitHub {
                  owner = "intel";
                  repo = "ipp-crypto";
                  rev = "ippcp_${version}";
                  inherit hash;
                };
              }
            );

        libtomcryptBuilder =
          {
            tcVersion,
            tcHash,
            tmVersion,
            tmHash,
          }:
          (pkgs.libtomcrypt.override {
            libtommath = libtommathBuilder {
              version = tmVersion;
              hash = tmHash;
            };
          }).overrideAttrs
            (
              final: prev:
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
                preBuild =
                  if tcVersion != null then
                    if builtins.hasAttr (getMajorMinor tcVersion) preBuilds then
                      preBuilds."${getMajorMinor tcVersion}"
                    else
                      preBuilds."1.17"
                  else
                    preBuilds."1.18";
              in
              rec {
                makefile = "makefile.unix";
                version = if tcVersion != null then tcVersion else prev.version;

                src =
                  if version == prev.version then
                    prev.src
                  else
                    pkgs.fetchFromGitHub {
                      owner = "libtom";
                      repo = "libtomcrypt";
                      rev = if pkgs.lib.hasPrefix "1.18" version then "refs/tags/v${version}" else "refs/tags/${version}";
                      hash = tcHash;
                    };

                inherit preBuild;
                patches =
                  if pkgs.lib.hasPrefix "1.18" version then
                    (prev.patches or [ ])
                    ++ [
                      # NOTE: LibTomCrypt does not expose the lib, when built statically (using `makefile and not `makefile.shared`).
                      #       This patch copies the necessary code from `makefile.shared`.
                      ./nix/libtomcrypt-pkgconfig-for-static.patch
                    ]
                  else
                    [ ];
              }
            );

        libtommathBuilder =
          { version, hash }:
          pkgs.libtommath.overrideAttrs (
            final: prev: rec {
              makefile = "makefile.unix";
              # version = if version != null then version else prev.version;
              version = "1.3.0";
              src = pkgs.fetchurl {
                url = "https://github.com/libtom/libtommath/releases/download/v${version}/ltm-${version}.tar.xz";
                # hash = if hash != null then hash else prev.hash;
                hash = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg";
              };
              patches = (prev.patches or [ ]) ++ [
                # NOTE: LibTomMath does not expose the lib, when built statically (using `makefile and not `makefile.shared`).
                #       This patch copies the necessary code from `makefile.shared`.
                ./nix/libtommath-pkgconfig-for-static-build.patch
              ];
            }
          );
        # NOTE: should gmp library be also dependent?
        nettleBuilder =
          {
            version ? null,
            tag ? null,
            hash ? null,
          }:
          if version == null then
            pkgs.nettle.overrideAttrs (
              final: prev: { configureFlags = (prev.configureFlags or [ ]) ++ [ "--enable-static" ]; }
            )
          else
            pkgs.nettle.overrideAttrs (
              final: prev: {
                inherit version;
                configureFlags = (prev.configureFlags or [ ]) ++ [ "--enable-static" ];
                src = pkgs.fetchurl {
                  url = "mirror://gnu/nettle/nettle-${version}.tar.gz";
                  inherit hash;
                };
              }
            );
        cryptoppBuilder =
          {
            version ? null,
            hash ? null,
          }:
          if version == null then
            (pkgs.cryptopp.override { enableStatic = true; })
          else
            (pkgs.cryptopp.override { enableStatic = true; }).overrideAttrs (
              final: prev: {
                version = pkgs.lib.strings.replaceStrings [ "_" ] [ "." ] version;
                src = pkgs.fetchFromGitHub {
                  owner = "weidai11";
                  repo = "cryptopp";
                  rev = "CRYPTOPP_${version}";
                  inherit hash;
                };
              }
            );
        libresslBuilder =
          {
            version ? null,
            hash ? null,
          }:
          if version == null then
            (pkgs.libressl.override { buildShared = false; }).overrideAttrs ({
              patches =
                if version == "3.8.2" then
                  [
                    (pkgs.fetchpatch {
                      url = "https://github.com/libressl/portable/commit/86e4965d7f20c3a6afc41d95590c9f6abb4fe788.patch";
                      includes = [ "tests/tlstest.sh" ];
                      hash = "sha256-XmmKTvP6+QaWxyGFCX6/gDfME9GqBWSx4X8RH8QbDXA=";
                    })
                  ]
                else
                  [ ];
            })
          else
            (pkgs.libressl.override { buildShared = false; }).overrideAttrs (
              final: prev: rec {
                src = pkgs.fetchurl {
                  url = "mirror://openbsd/LibreSSL/${prev.pname}-${version}.tar.gz";
                  inherit hash;
                };
                patches =
                  if version == "3.8.2" then
                    [
                      (pkgs.fetchpatch {
                        url = "https://github.com/libressl/portable/commit/86e4965d7f20c3a6afc41d95590c9f6abb4fe788.patch";
                        includes = [ "tests/tlstest.sh" ];
                        hash = "sha256-XmmKTvP6+QaWxyGFCX6/gDfME9GqBWSx4X8RH8QbDXA=";
                      })
                    ]
                  else
                    [ ];

                # NOTE: Due to name conflicts between OpenSSL and LibreSSL we need to resolve this manually.
                #       This is not needed for building the individual shims through Nix, as libresslShim build env does not
                #       contain OpenSSL at all, but for the interactive shell (started with `nix develop`), when multiple
                #       lib shims are built alongside each other.
                postFixup = pkgs.lib.concatLines [
                  (prev.postFixup or "")
                  ''
                    cp $dev/lib/pkgconfig/libcrypto.pc $dev/lib/pkgconfig/libresslcrypto.pc
                    sed --in-place --expression 's/-lcrypto/-lresslcrypto/' $dev/lib/pkgconfig/libresslcrypto.pc
                    ln -s $out/lib/libcrypto.so $out/lib/libresslcrypto.so
                    ln -s $out/lib/libcrypto.a $out/lib/libresslcrypto.a
                  ''
                ];

              }
            );
        gmp = pkgs.gmp.override { withStatic = true; };

        # Custom added packages
        wolfcryptjni =
          with customPkgs;
          wolfcrypt-jni.overrideAttrs (
            final: prev: {
              src = pkgs.fetchFromGitHub {
                owner = "wolfSSL";
                repo = "wolfcrypt-jni";
                rev = "0497ee767c994775beda2f2091009593961e5c7e";
                hash = "sha256-mtUXUyIKJ617WzAWjlOaMscWM7zuGBISVMEAbmQNBOg=";
              };
            }
          );

        # Shims and libs
        # Current list of targets: tomcrypt botan cryptopp openssl boringssl gcrypt mbedtls ippcp nettle libressl
        tomcryptShimBuilder =
          {
            tcVersion,
            tcHash,
            tmVersion,
            tmHash,
          }:
          pkgs.callPackage ./nix/tomcryptshim.nix {
            inherit pkgs;
            libtomcrypt = (
              libtomcryptBuilder {
                inherit
                  tcVersion
                  tcHash
                  tmVersion
                  tmHash
                  ;
              }
            );
            libtommath = (
              libtommathBuilder {
                version = tmVersion;
                hash = tmHash;
              }
            );
          };
        botanShimBuilder =
          {
            version,
            source_extension,
            hash,
          }:
          pkgs.callPackage ./nix/botanshim.nix {
            botan2 = botan2Builder { inherit version source_extension hash; };
          };
        cryptoppShimBuilder =
          { version, hash }:
          pkgs.callPackage ./nix/cryptoppshim.nix { cryptopp = cryptoppBuilder { inherit version hash; }; };
        opensslShimBuilder =
          { version, hash }:
          import ./nix/opensslshim.nix {
            inherit pkgs;
            openssl = (
              opensslBuilder {
                version = version;
                hash = hash;
              }
            );
          };
        boringsslShimBuilder =
          { rev, hash }:
          import ./nix/boringsslshim.nix {
            inherit pkgs;
            boringssl = (boringsslBuilder { inherit rev hash; });
          };
        gcryptShimBuilder =
          { version, hash }:
          import ./nix/gcryptshim.nix {
            inherit pkgs libgpg-error;
            libgcrypt = libgcryptBuilder { inherit version hash; };
          };
        mbedtlsShimBuilder =
          { version, hash }:
          import ./nix/mbedtlsshim.nix {
            inherit pkgs;
            mbedtls = (mbedtlsBuilder { inherit version hash; });
          };
        ippcpShimBuilder =
          { version, hash }:
          import ./nix/ippcpshim.nix {
            pkgs = pkgs;
            ipp-crypto = (ipp-cryptoBuilder { inherit version hash; });
          };
        nettleShimBuilder =
          {
            version,
            tag,
            hash,
          }:
          import ./nix/nettleshim.nix {
            inherit pkgs gmp;
            nettle = (nettleBuilder { inherit version tag hash; });
          };
        libresslShimBuilder =
          { version, hash }:
          import ./nix/libresslshim.nix {
            inherit pkgs;
            libressl = (libresslBuilder { inherit version hash; });
          };

        commonLibs = import ./nix/commonlibs.nix { pkgs = pkgs; };

        buildECTesterStandalone =
          {
            tomcrypt ? {
              version = null;
              hash = null;
            },
            tommath ? {
              version = null;
              hash = null;
            },
            botan ? {
              version = null;
              source_extension = null;
              hash = null;
            },
            cryptopp ? {
              version = null;
              hash = null;
            },
            openssl ? {
              version = null;
              hash = null;
            },
            boringssl ? {
              rev = null;
              hash = null;
            },
            gcrypt ? {
              version = null;
              hash = null;
            },
            mbedtls ? {
              version = null;
              hash = null;
            },
            ippcp ? {
              version = null;
              hash = null;
            },
            nettle ? {
              version = null;
              tag = null;
              hash = null;
            },
            libressl ? {
              version = null;
              hash = null;
            },
          }:
          (
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
              boringsslShim = boringsslShimBuilder { inherit (boringssl) rev hash; };
              gcryptShim = gcryptShimBuilder { inherit (gcrypt) version hash; };
              mbedtlsShim = mbedtlsShimBuilder { inherit (mbedtls) version hash; };
              ippcpShim = ippcpShimBuilder { inherit (ippcp) version hash; };
              nettleShim = nettleShimBuilder { inherit (nettle) version tag hash; };
              libresslShim = libresslShimBuilder { inherit (libressl) version hash; };
            in
            with pkgs;
            gradle2nix.builders.${system}.buildGradlePackage rec {
              pname = "ECTesterStandalone";
              version = "0.3.3";
              lockFile = ./gradle.lock;

              # NOTE: the shims are built separately, therefore no need to call build `libs` target
              gradleBuildFlags = [ ":standalone:uberJar" ];
              src = ./.;

              jniLibsPath = "standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/";

              #      shims = [ "tomcrypt" "botan" "cryptopp" "openssl" "boringssl" "gcrypt" "mbedtls" "ippcp" "nettle" "libressl" ];
              #      copyLib = libName:
              # ( if ${libName}.version != null then "cp ${libName}Shim.out/lib/libressl_provider.so ${jniLibsPath}" else "" )

              # FIXME add conditionally libs using map?
              preConfigure = pkgs.lib.concatLines [
                (if tomcrypt.version != null then "cp ${tomcryptShim.out}/lib/* ${jniLibsPath}" else "")
                (if botan.version != null then "cp ${botanShim.out}/lib/* ${jniLibsPath}" else "")
                (if cryptopp.version != null then "cp ${cryptoppShim.out}/lib/* ${jniLibsPath}" else "")
                (if openssl.version != null then "cp ${opensslShim.out}/lib/* ${jniLibsPath}" else "")
                (if boringssl.rev != null then "cp ${boringsslShim.out}/lib/* ${jniLibsPath}" else "")
                (if gcrypt.version != null then "cp ${gcryptShim.out}/lib/* ${jniLibsPath}" else "")
                (if mbedtls.version != null then "cp ${mbedtlsShim.out}/lib/* ${jniLibsPath}" else "")
                (if ippcp.version != null then "cp ${ippcpShim.out}/lib/* ${jniLibsPath}" else "")
                (if nettle.version != null then "cp ${nettleShim.out}/lib/* ${jniLibsPath}" else "")
                (if libressl.version != null then "cp ${libresslShim.out}/lib/* ${jniLibsPath}" else "")
                ''
                                  cp ${wolfcryptjni}/lib/* ${jniLibsPath}
                                  cp ${commonLibs}/lib/* ${jniLibsPath}
                  		''
              ];

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

            }
          );
        loadVersions =
          { libName, function }:
          let
            versions = builtins.fromJSON (builtins.readFile ./nix/${libName}_pkg_versions.json);
            firstVersion = builtins.elemAt (pkgs.lib.attrsets.attrValues versions) 0;
          in
          pkgs.lib.mapAttrs (rev: specs: function { ${libName} = specs; }) versions
          // {
            default = function { ${libName} = firstVersion; };
          };

        loadVersionsForShim =
          { libName, function }:
          let
            versions = builtins.fromJSON (builtins.readFile ./nix/${libName}_pkg_versions.json);
            firstVersion = builtins.elemAt (pkgs.lib.attrsets.attrValues versions) 0;
          in
          pkgs.lib.mapAttrs (rev: specs: function specs) versions
          // (with pkgs.lib; {
            default = function firstVersion;
          });
      in
      {
        packages = rec {
          default = openssl.default;
          tomcrypt = loadVersions {
            libName = "tomcrypt";
            function = buildECTesterStandalone;
          };
          botan = loadVersions {
            libName = "botan";
            function = buildECTesterStandalone;
          };
          cryptopp = loadVersions {
            libName = "cryptopp";
            function = buildECTesterStandalone;
          };
          openssl = loadVersions {
            libName = "openssl";
            function = buildECTesterStandalone;
          };
          boringssl = loadVersions {
            libName = "boringssl";
            function = buildECTesterStandalone;
          };
          gcrypt = loadVersions {
            libName = "gcrypt";
            function = buildECTesterStandalone;
          };
          mbedtls = loadVersions {
            libName = "mbedtls";
            function = buildECTesterStandalone;
          };
          ippcp = loadVersions {
            libName = "ippcp";
            function = buildECTesterStandalone;
          };
          nettle = loadVersions {
            libName = "nettle";
            function = buildECTesterStandalone;
          };
          libressl = loadVersions {
            libName = "libressl";
            function = buildECTesterStandalone;
          };

          shim = {
            tomcrypt = loadVersionsForShim {
              libName = "tomcrypt";
              function = tomcryptShimBuilder;
            };
            botan = loadVersionsForShim {
              libName = "botan";
              function = botanShimBuilder;
            };
            cryptopp = loadVersionsForShim {
              libName = "cryptopp";
              function = cryptoppShimBuilder;
            };
            openssl = loadVersionsForShim {
              libName = "openssl";
              function = opensslShimBuilder;
            };
            boringssl = loadVersionsForShim {
              libName = "boringssl";
              function = boringsslShimBuilder;
            };
            gcrypt = loadVersionsForShim {
              libName = "gcrypt";
              function = gcryptShimBuilder;
            };
            mbedtls = loadVersionsForShim {
              libName = "mbedtls";
              function = mbedtlsShimBuilder;
            };
            ippcp = loadVersionsForShim {
              libName = "ippcp";
              function = ippcpShimBuilder;
            };
            nettle = loadVersionsForShim {
              libName = "nettle";
              function = nettleShimBuilder;
            };
            libressl = loadVersionsForShim {
              libName = "libressl";
              function = libresslShimBuilder;
            };
          };

          lib = {
            tomcrypt = loadVersionsForShim {
              libName = "tomcrypt";
              function = libtomcryptBuilder;
            };
            botan = loadVersionsForShim {
              libName = "botan";
              function = botan2Builder;
            };
            cryptopp = loadVersionsForShim {
              libName = "cryptopp";
              function = cryptoppBuilder;
            };
            openssl = loadVersionsForShim {
              libName = "openssl";
              function = opensslBuilder;
            };
            boringssl = loadVersionsForShim {
              libName = "boringssl";
              function = boringsslBuilder;
            };
            gcrypt = loadVersionsForShim {
              libName = "gcrypt";
              function = libgcryptBuilder;
            };
            mbedtls = loadVersionsForShim {
              libName = "mbedtls";
              function = mbedtlsBuilder;
            };
            ippcp = loadVersionsForShim {
              libName = "ippcp";
              function = ipp-cryptoBuilder;
            };
            nettle = loadVersionsForShim {
              libName = "nettle";
              function = nettleBuilder;
            };
            libressl = loadVersionsForShim {
              libName = "libressl";
              function = libresslBuilder;
            };
          };

          fetchReleases =
            with pkgs.python3Packages;
            buildPythonApplication {
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

          buildAll =
            with pkgs.python3Packages;
            buildPythonApplication {
              pname = "buildAll";
              version = "0.1.0";
              format = "other";

              propagatedBuildInputs = [
                ipython
                pudb
              ];

              src = ./test_building_all.py;
              dontUnpack = true;
              installPhase = ''
                install -Dm755 $src $out/bin/$pname
              '';
            };

        };
        devShells.default =
          with pkgs;
          mkShell rec {
            nativeBuildInputs = [ pkg-config ];

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
              (opensslBuilder { })
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

            LD_LIBRARY_PATH =
              with pkgs;
              pkgs.lib.makeLibraryPath [
                libtommath
                libtomcrypt
                botan2
                cryptopp
                (opensslBuilder { })
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