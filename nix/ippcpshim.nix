{ pkgs, ipp-crypto }:
with pkgs;
stdenv.mkDerivation rec {
  name = "IppCryptoShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    ipp-crypto
    pkg-config
    jdk11_headless
  ];

  IPP_CRYPTO_HEADER = "${ipp-crypto.dev}/include";
  IPP_CRYPTO_LIB = "${ipp-crypto}/lib/";

  buildPhase = ''
    make ippcp
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp ippcp_provider.so $out/lib
  '';
}
