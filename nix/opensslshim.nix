{ pkgs, openssl }:
with pkgs;
stdenv.mkDerivation {
  name = "OpenSSLShim-${openssl.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    openssl
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make openssl
  '';

  OPENSSL_CFLAGS = ''
    -DECTESTER_OPENSSL_${builtins.replaceStrings ["."] ["_"] openssl.version}=1 \
    -DECTESTER_OPENSSL_MAJOR=${pkgs.lib.versions.major openssl.version} \
    -DECTESTER_OPENSSL_MINOR=${pkgs.lib.versions.minor openssl.version} \
    -DECTESTER_OPENSSL_PATCH=${pkgs.lib.versions.patch openssl.version} \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp openssl_provider.so $out/lib/
  '';
}
