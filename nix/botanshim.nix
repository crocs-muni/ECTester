{
  pkgs,
  botan2
}:
with pkgs;
stdenv.mkDerivation {
  name = "BotanShim-${botan2.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    botan2
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make botan
  '';

  BOTAN_CXXFLAGS = ''
    -DECTESTER_BOTAN_${builtins.replaceStrings ["."] ["_"] botan2.version}=1 \
    -DECTESTER_BOTAN_MAJOR=${pkgs.lib.versions.major botan2.version} \
    -DECTESTER_BOTAN_MINOR=${pkgs.lib.versions.minor botan2.version} \
    -DECTESTER_BOTAN_PATCH=${pkgs.lib.versions.patch botan2.version} \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp botan_provider.so $out/lib/
  '';
}
