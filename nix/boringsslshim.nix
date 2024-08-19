{ pkgs, boringssl }:
with pkgs;
stdenv.mkDerivation {
  name = "BoringSSLShim-${boringssl.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    boringssl
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make boringssl
  '';

  BORINGSSL_CFLAGS = ''
    -I${boringssl.dev.outPath}/include \
    -DECTESTER_BORINGSSL_${boringssl.version}=1 \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp boringssl_provider.so $out/lib
  '';
}
