{
  pkgs
  , mbedtls
}:
with pkgs; stdenv.mkDerivation rec {
  name = "MbedTLSShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    mbedtls
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make mbedtls
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp mbedtls_provider.so $out/lib
  '';
}
