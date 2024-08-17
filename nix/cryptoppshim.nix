{ pkgs, cryptopp }:
with pkgs;
let 
  dotVersion = builtins.replaceStrings ["_"] ["."] cryptopp.version;
in
stdenv.mkDerivation {
  name = "Crypto++ Shim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    cryptopp
    pkg-config
    jdk
  ];

  buildPhase = ''
    make cryptopp
  '';

  CRYPTOPP_CXXFLAGS = ''
    -DECTESTER_CRYPTOPP_${cryptopp.version}=1 \
    -DECTESTER_CRYPTOPP_MAJOR=${pkgs.lib.versions.major dotVersion} \
    -DECTESTER_CRYPTOPP_MINOR=${pkgs.lib.versions.minor dotVersion} \
    -DECTESTER_CRYPTOPP_PATCH=${pkgs.lib.versions.patch dotVersion} \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp cryptopp_provider.so $out/lib/
  '';
}
