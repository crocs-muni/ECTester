{ pkgs, mbedtls }:
with pkgs;
stdenv.mkDerivation rec {
  name = "MbedTLSShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;
  rawVersion = pkgs.lib.strings.removePrefix "v" mbedtls.version;

  buildInputs = [
    mbedtls
    pkg-config
    jdk11_headless
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
