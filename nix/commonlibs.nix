{ pkgs }:
with pkgs;
stdenv.mkDerivation rec {
  name = "Common Libraries";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    pkg-config
    cmake
    which
    jdk17_headless
  ];

  dontUseCmakeConfigure = true;

  libs = "lib_cppsignals.so lib_csignals.so lib_timing.so";

  buildPhase = ''
    make ${libs}
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp ${libs} $out/lib
  '';
}
