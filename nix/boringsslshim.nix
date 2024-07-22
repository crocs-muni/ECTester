{
  pkgs
  , boringssl
}:
with pkgs; stdenv.mkDerivation {
  name = "BoringSSLShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    boringssl
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make boringssl
  '';

  BORINGSSL_CFLAGS = "${boringssl.dev.outPath}/include";
  # LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [
  #   boringssl
  # ];

  installPhase = ''
    mkdir --parents $out/lib
    cp boringssl_provider.so $out/lib
  '';
}
