{
  stdenv,
  botan2,
  pkg-config,
  jdk,
}:
stdenv.mkDerivation {
  name = "BotanShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    botan2
    pkg-config
    jdk
  ];

  buildPhase = ''
    make botan
  '';

  BOTAN_CXXFLAGS = "-DECTESTER_BOTAN_${builtins.replaceStrings ["."] ["_"] botan2.version}=1";

  installPhase = ''
    mkdir --parents $out/lib
    cp botan_provider.so $out/lib/
  '';
}
