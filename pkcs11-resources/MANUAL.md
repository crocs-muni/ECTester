# ECTester PKCS#11 manual

## 1. Arbitrary PKCS#11 implementation usage

* `--pkcs11-path < implementationPath >`
<br> Specify the path to .so (or .dll for Windows). If own configuration is provided, the path is ignored.
* `--pkcs11-name < implementationName >`
<br> Specify the name of the implementation. If own configuration is provided, the path is ignored.
* `--pkcs11-login < PIN >`
<br> Specify the user PIN for logging into an implementation. Required for most crypto operations.
If not provided, ECTester assumes the implementation does not require logging in.
* `--pkcs11-cfg < configPath >`
<br> Specify an own SunPKCS11 config. If not provided, ECTester tries to create a default configuration file based on previous experiences.

## 2. Supported PKCS#11 implementations usage

* Usage similiar to other SW libraries supported by ECTester with few specialities specified bellow
* Compiled shared objects are part of the tool, located in `standalone/src/main/resources/cz/crcs/ectester/standalone/libs/pkcs11/`
* Run the tool using the standard command `java -jar standalone/build/libs/ECTesterStandalone.jar <options> [one of the following lib names]`
* Another way to run the tool is using Nix with `nix run .#softhsm -- <options>`, for example:

    ```
    nix run .#softhsm -- ecdsa --amount 10 --curve-name secp256k1 --type SHA3-256withECDSA softhsm
    ```

### 2.1 SoftHSMv2-OPENSSL

* Compiled using OpenSSL backend
* Assumes `SOFTHSM2_CONF` is set to `~/.local/share/ECTesterStandalone/SoftHSMv2-OPENSSL.conf` or your own SoftHSMv2 configuration.
In that case we assume you manage your own cryptoki, and therefore you need to set `SOFTHSM2_PIN` to PIN of the initialized cryptoki.
* If `SOFTHSM2_CONF` is set to our location, ECTester initializes a fresh cryptoki for each run, to izolate test runs

### 2.2 SoftHSMv2-BOTAN

* Compiled using Botan backend
* Assumes `SOFTHSM2_CONF` is set to `~/.local/share/ECTesterStandalone/SoftHSMv2-OPENSSL.conf` or your own SoftHSMv2 configuration.
  In that case we assume you manage your own cryptoki, and therefore you need to set `SOFTHSM2_PIN` to PIN of the initialized cryptoki.
* If `SOFTHSM2_CONF` is set to our location, ECTester initializes a fresh cryptoki for each run, to izolate test runs
* Botan backend SEG faults after our testing and creates an error log (even after being just initialized, therefore is commented out from the libs in source code, to prevent the SEG fault after just listing libs)
* NOTE: it SEG faults even when called using its C api, therefore problem is probably in the library itself (issue is double free of memory on cleanup)

### 2.3 wolfPKCS11

* Compiled using WolfSSL backend
* Pre-configured token, no PIN required
* Assumes `WOLFPKCS11_TOKEN_PATH` is set to `~/.local/share/ECTesterStandalone/wolfpkcs11-token`
* ECTester creates a fresh temporary directory for the token, to isolate test runs
* Has library-side hardcoded limit of 64 objects, therefore after some testing it starts crashing because it is not able to generate any new keys
* Solution to this is to delete contents of `WOLFPKCS11_TOKEN_PATH` and reinit the token using `pkcs11-tool`
