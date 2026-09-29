{
  lib,
  runtimeShell,
  writeShellApplication,

  softhsm,
  ectester,

  botan3,
  openssl,
  sqlite,

  backend ? "openssl",
}:
let
  checkedBackend =
    if builtins.elem backend [ "openssl" ] then
      backend
    else
      throw ''
        Unless botan3 is supported by SoftHSMv2, see https://github.com/softhsm/SoftHSMv2/issues/792
        the only supported backend is 'openssl'.
      '';
  softhsmPkg =
    if checkedBackend == "openssl" then
      softhsm
    else if checkedBackend == "botan" then
      softhsm.overrideAttrs (prev: rec {

        buildInputs = [
          botan3
          sqlite
        ];

        sansBackendConfigureFlags = builtins.filter (
          f: !((lib.hasPrefix "--with-crypto" f) || (lib.hasPrefix "--with-openssl" f))
        ) prev.configureFlags;

        configureFlags = sansBackendConfigureFlags ++ [
          "--with-crypto-backend=botan"
          "--with-botan=${lib.getDev botan3}"
        ];
      })
    else
      throw "The only supported values for backend are 'openssl' or 'botan'.";
in
writeShellApplication {
  name = "ECTesterStandalone";

  runtimeInputs = [ softhsmPkg ];

  text = ''
    SOFTHSM2_TEMPDIR=$(mktemp --directory)
    SOFTHSM2_CONF="$HOME/.local/share/ECTesterStandalone/SoftHSMv2-OPENSSL.conf"
    SOFTHSM2_LIB="${softhsmPkg}/lib/softhsm/libsofthsm2.so"
    PIN=1234

    export SOFTHSM2_CONF SOFTHSM2_LIB PIN ECTESTER_NIX

    cat <<EOF > "$SOFTHSM2_TEMPDIR"/softhsm2.conf
    directories.tokendir = $SOFTHSM2_TEMPDIR/tokens
    objectstore.backend = file
    objectstore.umask = 0077

    # ERROR, WARNING, INFO, DEBUG
    log.level = ERROR

    # If CKF_REMOVABLE_DEVICE flag should be set
    slots.removable = false

    # Enable and disable PKCS#11 mechanisms using slots.mechanisms.
    slots.mechanisms = ALL

    # If the library should reset the state on fork
    library.reset_on_fork = false
    EOF


    ${ectester.outPath}/bin/ECTesterStandalone "$@"
    rm --recursive --force "$SOFTHSM2_TEMPDIR"
  '';
}
