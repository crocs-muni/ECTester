{ pkgs, libressl }:
with pkgs;
stdenv.mkDerivation rec {
  name = "LibreSSLShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    libressl
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make libressl
  '';

  LIBRESSL_CFLAGS = "-DECTESTER_LIBRESSL_${builtins.replaceStrings ["."] ["_"] libressl.version}=1";

  installPhase = ''
    mkdir --parents $out/lib
    cp libressl_provider.so $out/lib
  '';
}
