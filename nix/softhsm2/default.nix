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

  # FIXME Only do the setup when we don't receive any tokens In case the
  # SOFTHSM2_CONF is not set, we create both the SoftHSMv2 configuration and
  # also initialize the token. It is done for each invocation, thus there is no
  # persistence between the tokens with this invocation.

  text = ''
    create_softhsm_config () {
      cat <<EOF > "$SOFTHSM2_CONF"
      directories.tokendir = $SOFTHSM2_TOKEN_DIR
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
    }

    if [ -z "''${SOFTHSM2_CONF:-}" ]; then
      printf "SOFTHSM2_CONF is empty or not set, creating ephemeral SoftHSMv2 configuration and token.\n" >&2

      SOFTHSM2_TEMPDIR=$(mktemp --directory)
      SOFTHSM2_TOKEN_DIR="$SOFTHSM2_TEMPDIR/tokens"
      SOFTHSM2_CONF="$SOFTHSM2_TEMPDIR/softhsmv2.conf"
      SOFTHSM2_LIB="${softhsmPkg}/lib/softhsm/libsofthsm2.so"
      SOFTHSM2_PIN=1234

      export SOFTHSM2_CONF SOFTHSM2_LIB SOFTHSM2_PIN ECTESTER_NIX
      mkdir --parents "$SOFTHSM2_TOKEN_DIR"

      # shellcheck disable=SC2329  # it's a TRAP
      cleanup() {
          rm --recursive --force "$SOFTHSM2_TEMPDIR"
      }
      trap cleanup EXIT

      create_softhsm_config

      softhsm2-util --module "$SOFTHSM2_LIB" \
        --init-token --label "ECTester-SoftHSMv2-OPENSSL" \
        --slot 0 --so-pin "$SOFTHSM2_PIN" --pin "$SOFTHSM2_PIN" > /dev/null
    fi

    ${ectester.outPath}/bin/ECTesterStandalone "$@"
  '';
}
