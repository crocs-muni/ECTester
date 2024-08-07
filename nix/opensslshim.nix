{ pkgs, openssl }:
with pkgs;
stdenv.mkDerivation {
  name = "OpenSSL Shim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    openssl
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make openssl
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp openssl_provider.so $out/lib/
  '';
}
