{
   pkgs
  , nettle
}:
with pkgs; stdenv.mkDerivation rec {
  name = "NettleShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    nettle
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make nettle
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp nettle_provider.so $out/lib
  '';
}
