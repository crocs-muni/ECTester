{
  pkgs,
  nettle,
  gmp,
}:
with pkgs;
stdenv.mkDerivation rec {
  name = "NettleShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    nettle
    gmp
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make nettle
  '';

  NETTLE_CFLAGS = "-DECTESTER_NETTLE_${builtins.replaceStrings ["."] ["_"] nettle.version}=1";

  installPhase = ''
    mkdir --parents $out/lib
    cp nettle_provider.so $out/lib
  '';
}
