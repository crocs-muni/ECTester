{
  pkgs
}:
with pkgs; stdenv.mkDerivation {
  name = "BotanShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    botan2
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make botan
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp botan_provider.so $out/lib/
  '';
}
