{
  pkgs,
  libgcrypt,
  libgpg-error,
}:
with pkgs;
stdenv.mkDerivation {
  name = "GcryptShim-${libgcrypt.version}";
  src = ../standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni;

  buildInputs = [
    libgcrypt
    libgpg-error
    pkg-config
    pkgs.jdk_headless
  ];

  buildPhase = ''
    make gcrypt
  '';

  LIBGCRYPT_CFLAGS = ''
    -DECTESTER_LIBGCRYPT_${builtins.replaceStrings ["."] ["_"] libgcrypt.version}=1 \
    -DECTESTER_LIBGCRYPT_MAJOR=${pkgs.lib.versions.major libgcrypt.version} \
    -DECTESTER_LIBGCRYPT_MINOR=${pkgs.lib.versions.minor libgcrypt.version} \
    -DECTESTER_LIBGCRYPT_PATCH=${pkgs.lib.versions.patch libgcrypt.version} \
  '';

  installPhase = ''
    mkdir --parents $out/lib
    cp gcrypt_provider.so $out/lib/
  '';
}
