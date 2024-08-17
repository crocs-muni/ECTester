{ pkgs, openssl }:
with pkgs;
stdenv.mkDerivation {
  name = "OpenSSL Shim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    openssl
    pkg-config
    jdk
  ];

  buildPhase = ''
    make openssl
  '';

  OPENSSL_CFLAGS = "-DECTESTER_OPENSSL_${builtins.replaceStrings ["."] ["_"] openssl.version}=1";

  installPhase = ''
    mkdir --parents $out/lib
    cp openssl_provider.so $out/lib/
  '';
}
