{ pkgs, mbedtls }:
with pkgs;
let
  rawVersion = pkgs.lib.strings.removePrefix "v" mbedtls.version;
in
stdenv.mkDerivation rec {
  name = "MbedTLSShim-${mbedtls.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;


  buildInputs = [
    mbedtls
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make mbedtls
  '';

  MBEDTLS_CFLAGS = ''
    -DECTESTER_MBEDTLS_${builtins.replaceStrings ["."] ["_"] rawVersion}=1 \
    -DECTESTER_MBEDTLS_MAJOR=${pkgs.lib.versions.major rawVersion} \
    -DECTESTER_MBEDTLS_MINOR=${pkgs.lib.versions.minor rawVersion} \
    -DECTESTER_MBEDTLS_PATCH=${pkgs.lib.versions.patch rawVersion} \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp mbedtls_provider.so $out/lib
  '';
}
