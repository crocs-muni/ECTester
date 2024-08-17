{ pkgs, ipp-crypto }:
with pkgs;
stdenv.mkDerivation rec {
  name = "IppCryptoShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    ipp-crypto
    pkg-config
    jdk
  ];

  IPP_CRYPTO_CFLAGS = "-I${ipp-crypto.dev}/include -DECTESTER_IPPCP_VERSION=${ipp-crypto.version}";
  IPP_CRYPTO_LFLAGS = "-L${ipp-crypto}/lib/";

  buildPhase = ''
    make ippcp
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp ippcp_provider.so $out/lib
  '';
}
