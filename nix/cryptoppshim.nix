{ pkgs, cryptopp }:
with pkgs;
stdenv.mkDerivation {
  name = "Crypto++ Shim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    cryptopp
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make cryptopp
  '';

  CRYPTOPP_CXXFLAGS = "-DECTESTER_CRYPTOPP_${cryptopp.version}=1";

  installPhase = ''
    mkdir --parents $out/lib
    cp cryptopp_provider.so $out/lib/
  '';
}
