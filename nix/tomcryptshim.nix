{
  pkgs,
  libtomcrypt,
  libtommath,
}:
with pkgs;
stdenv.mkDerivation {
  name = "TomCryptShim-${libtomcrypt.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    libtommath
    libtomcrypt
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make tomcrypt
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp tomcrypt_provider.so $out/lib
  '';
}
