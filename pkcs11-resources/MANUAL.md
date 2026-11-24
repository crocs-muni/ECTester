# ECTester PKCS#11 manual

## Arbitrary PKCS#11 implementation usage

* `--pkcs11-path < implementationPath >`
<br> Specify the path to .so (or .dll for Windows). If own configuration is provided, the path is ignored.
* `--pkcs11-name < implementationName >`
<br> Specify the name of the implementation. If own configuration is provided, the path is ignored.
* `--pkcs11-login < PIN >`
<br> Specify the user PIN for logging into an implementation. Required for most crypto operations.
If not provided, ECTester assumes the implementation does not require logging in.
* `--pkcs11-cfg < configPath >`
<br> Specify an own SunPKCS11 config. If not provided, ECTester tries to create a default configuration file based on previous experiences.

### Example custom PKCS#11 target

Because ECTester already supports SoftHSMv2, and it is conveniently provided as
Git submodule, we will use it for the example. Nonetheless, this example should
be easy to update to other PKCS#11 targets. All the code examples are assuming
the user is in the root directory after cloning the project.

1. Build SoftHSMv2 shared object:

    ```bash
    pushd ext/SoftHSMv2
    mkdir --parents build
    sh autogen.sh
    ./configure --enable-ecc --enable-sha3 --with-crypto-backend=openssl
    make -j$(nproc)
    popd
    ```

The `libsofthsm2.so` should be available in `ext/SoftHSMv2/src/lib/.libs/libsofthsm2.so`.

2. SoftHSMv2 requires a configuration file and we store
   the tokens data inside directory:

    ```bash
    mkdir ./tokens
    cat <<EOF > ./softhsm2.conf
      directories.tokendir = $(realpath ./tokens)
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
    ```

3.  Set SoftHSMv2 enviromental variables, create and initialize the software token:

    ```bash
    export SOFTHSM2_CONF=$(realpath ./softhsm2.conf)
    ./ext/SoftHSMv2/src/bin/util/softhsm2-util --module ./ext/SoftHSMv2/src/lib/.libs/libsofthsm2.so \
        --label test --slot 0 --so-pin 1234 --pin 1234 --init-token
    The token has been initialized and is reassigned to slot 109148356
    ```

4. SunPKCS11 provider that is used in ECTester requires it's own configuration. Create an exaple one for SoftHSMv2:

    ```bash
    cat <<EOF > sunpkcs11-softhsm.cfg
    name = softhsm
    library = $(realpath ./ext/SoftHSMv2/src/lib/.libs/libsofthsm2.so)
    attributes(generate, CKO_PRIVATE_KEY, *) = {
      CKA_EXTRACTABLE = true
      CKA_SIGN = true
      CKA_SENSITIVE = false
      CKA_DERIVE = true
    }
    attributes(generate, CKO_SECRET_KEY, *) = {
      CKA_EXTRACTABLE = true
      CKA_SENSITIVE = false
    }
    EOF
    ```

5. At this point testing the SoftHSMv2 token is possible. There are a number of
   ways to now invoke `ECTesterStandalone` against the PKCS#11 target. The
   following three examples show the exact same usage.

   Using Nix you can run against the target directly:

    ```bash
    nix run .# -- --pkcs11-path $(realpath ./ext/SoftHSMv2/src/lib/.libs/libsofthsm2.so) \
        --pkcs11-name softhsm --pkcs11-login 1234 --pkcs11-cfg sunpkcs11-softhsm.cfg \
        ecdsa --amount 10 --curve-name secp256k1 --type SHA3-256withECDSA softhsm
    ```

   Or build and run separately:

    ```bash
    nix build
    ./result/bin/ECTesterStandalone --pkcs11-path $(realpath ./ext/SoftHSMv2/src/lib/.libs/libsofthsm2.so) \
        --pkcs11-name softhsm --pkcs11-login 1234 --pkcs11-cfg sunpkcs11-softhsm.cfg \
        ecdsa --amount 10 --curve-name secp256k1 --type SHA3-256withECDSA softhsm
    ```

   You can also build `ECTesterStandalone` using Gradle and run that:

    ```bash
    ./gradlew :standalone:uberJar
    java -jar ./standalone/build/libs/ECTesterStandalone.jar \
        --pkcs11-path $(realpath ./ext/SoftHSMv2/src/lib/.libs/libsofthsm2.so) \
        --pkcs11-name softhsm --pkcs11-login 1234 --pkcs11-cfg customConfig.cfg \
        ecdsa --amount 10 --curve-name secp256k1 --type SHA3-256withECDSA softhsm
    ```

6. Finally, to clean up the SoftHSMv2 related variables and data:

    ```bash
    unset SOFTHSM2_CONF
    rm --recursive --force ./tokens
    ```

## Supported PKCS#11 implementations usage

* Usage similiar to other SW libraries supported by ECTester with few specialities specified bellow
* Compiled shared objects are part of the tool, located in `standalone/src/main/resources/cz/crcs/ectester/standalone/libs/pkcs11/`
* Run the tool using the standard command `java -jar standalone/build/libs/ECTesterStandalone.jar <options> [one of the following lib names]`
* Another way to run the tool is using Nix with `nix run .#softhsm -- <options>`, which does not require any further installation apart from Nix. For example, to generate 10 random ECDSA signatures using the SHA3-256 hash function and SECP256k1 curve:

    ```
    nix run .#softhsm -- ecdsa --amount 10 --curve-name secp256k1 --type SHA3-256withECDSA softhsm
    ```

### SoftHSMv2-OPENSSL

* Compiled using OpenSSL backend
* Assumes `SOFTHSM2_CONF` is set to `~/.local/share/ECTesterStandalone/SoftHSMv2-OPENSSL.conf` or your own SoftHSMv2 configuration.
In that case we assume you manage your own cryptoki, and therefore you need to set `SOFTHSM2_PIN` to PIN of the initialized cryptoki.
* If `SOFTHSM2_CONF` is set to our location, ECTester initializes a fresh cryptoki for each run, to isolate test runs

### SoftHSMv2-BOTAN

* Compiled using Botan backend
* Assumes `SOFTHSM2_CONF` is set to `~/.local/share/ECTesterStandalone/SoftHSMv2-OPENSSL.conf` or your own SoftHSMv2 configuration.
  In that case we assume you manage your own cryptoki, and therefore you need to set `SOFTHSM2_PIN` to PIN of the initialized cryptoki.
* If `SOFTHSM2_CONF` is set to our location, ECTester initializes a fresh cryptoki for each run, to isolate test runs
* Botan backend SEG faults after our testing and creates an error log (even after being just initialized, therefore is commented out from the libs in source code, to prevent the SEG fault after just listing libs)
* NOTE: it SEG faults even when called using its C api, therefore problem is probably in the library itself (issue is double free of memory on cleanup)
* The support for Botan backend is not guaranteed, because Botan 2.x is EOL and Botan 3.x support is [yet to be implemented](https://github.com/softhsm/SoftHSMv2/issues/792) in SoftHSM.

### WolfPKCS11

* Compiled using WolfSSL backend
* Pre-configured token, no PIN required
* Assumes `WOLFPKCS11_TOKEN_PATH` is set to `~/.local/share/ECTesterStandalone/wolfpkcs11-token`
* ECTester creates a fresh temporary directory for the token, to isolate test runs
* Has library-side hardcoded limit of 64 objects, therefore after some testing it starts crashing because it is not able to generate any new keys
* Solution to this is to delete contents of `WOLFPKCS11_TOKEN_PATH` and reinit the token using `pkcs11-tool`
