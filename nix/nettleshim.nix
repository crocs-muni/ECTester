{
  pkgs,
  nettle,
  gmp,
}:
with pkgs;
stdenv.mkDerivation rec {
  name = "NettleShim-${nettle.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    nettle
    gmp
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make nettle
  '';

  NETTLE_CFLAGS = ''
    -DECTESTER_NETTLE_${builtins.replaceStrings ["."] ["_"] nettle.version}=1 \
    -DECTESTER_NETTLE_MAJOR=${pkgs.lib.versions.major nettle.version} \
    -DECTESTER_NETTLE_MINOR=${pkgs.lib.versions.minor nettle.version} \
    -DECTESTER_NETTLE_PATCH=${pkgs.lib.versions.patch nettle.version} \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp nettle_provider.so $out/lib
  '';
}
