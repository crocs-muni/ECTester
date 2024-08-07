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

  installPhase = ''
    mkdir --parents $out/lib
    cp cryptopp_provider.so $out/lib/
  '';
}
