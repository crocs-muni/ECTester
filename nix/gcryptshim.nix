{
  pkgs
  , libgcrypt
  , libgpg-error
}:
with pkgs; stdenv.mkDerivation {
  name = "Gcrypt Shim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    libgcrypt
    libgpg-error
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make gcrypt
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp gcrypt_provider.so $out/lib/
  '';
}
