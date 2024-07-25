{
  pkgs
  , libtomcrypt
  , libtommath
}:
with pkgs; stdenv.mkDerivation {
  name = "TomCryptShim";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    libtommath
    libtomcrypt
    pkg-config
    jdk11_headless
  ];

  buildPhase = ''
    make tomcrypt
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp tomcrypt_provider.so $out/lib
  '';
}
