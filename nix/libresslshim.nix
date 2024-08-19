{ pkgs, libressl }:
with pkgs;
stdenv.mkDerivation rec {
  name = "LibreSSLShim-${libressl.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    libressl
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make libressl
  '';

  LIBRESSL_CFLAGS = ''
    -DECTESTER_LIBRESSL_${builtins.replaceStrings ["."] ["_"] libressl.version}=1 \
    -DECTESTER_LIBRESSL_MAJOR=${pkgs.lib.versions.major libressl.version} \
    -DECTESTER_LIBRESSL_MINOR=${pkgs.lib.versions.minor libressl.version} \
    -DECTESTER_LIBRESSL_PATCH=${pkgs.lib.versions.patch libressl.version} \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp libressl_provider.so $out/lib
  '';
}
