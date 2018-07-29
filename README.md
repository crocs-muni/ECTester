# ECTester
[![Build status](https://api.travis-ci.org/crocs-muni/ECTester.svg?branch=master)](https://travis-ci.org/crocs-muni/ECTester)  [![GitHub release](https://img.shields.io/github/release/crocs-muni/ECTEster.svg)](https://github.com/crocs-muni/ECTester/releases)  [![license](https://img.shields.io/github/license/crocs-muni/ECTester.svg)](https://github.com/crocs-muni/ECTester/blob/master/LICENSE) [![docs](https://img.shields.io/badge/docs-github.io-brightgreen.svg)](https://crocs-muni.github.io/ECTester/)

Tests support and behavior of elliptic curve cryptography implementations on JavaCards (`TYPE_EC_FP` and `TYPE_EC_F2M`) and on selected software libraries.
For more information on ECC support on JavaCards see the [github page](https://crocs-muni.github.io/ECTester/), with results, tables and docs.

## Build

ECTester uses ant. There are three parts of ECTester, the JavaCard applet used for testing, the reader app which controls it and the standalone app which tests software libraries.
```bash
git submodule update --init --recursive       # To initialize submodules.
ant -f build-reader.xml package               # To build the reader tool (jar) -> "dist/ECTesterReader.jar"
ant -f build-standalone.xml package           # To build the standalone tool (jar) -> "dist/ECTesterStandalone.jar"
ant -f build-applet.xml build                 # To build the applet (cap) -> "applet/ectester.cap".
```
Build produces both a lightweight version of the JARs and a full version of the JARs with dependencies included, the latter has the `*-dist.jar` suffix.
The standalone build tries building test binaries for all the supported libraries, and silently fails if the library is not properly supported.

## JavaCard testing

1. Upload `!uploader/ectester.cap` using your favorite tool (e.g., [GlobalPlatformPro tool](https://github.com/martinpaljak/GlobalPlatform))
2. Run `java -jar dist/ECTesterReader.jar -t`
3. Inspect output log with annotated results

Following operations are tested:
- Allocation of new KeyPair class for specified parameters
- Generation of KeyPair with default curve
- Setting of custom curve and KeyPair generation
- Generation of shared secret via ECDH
- Signature via ECDSA

See `java -jar ECTesterReader.jar -h` for more.

### Options

```
 -dsa,--ecdsa <count>              Sign data with ECDSA, [count] times.
 -t,--test <test_suite>            Test ECC support. [test_suite]:
                                   - default:
                                   - invalid:
                                   - compression:
                                   - twist:
                                   - degenerate:
                                   - cofactor:
                                   - wrong:
                                   - composite:
                                   - test-vectors:
 -dh,--ecdh <count>                Do EC KeyAgreement (ECDH...), [count]
                                   times.
 -e,--export                       Export the defaut curve parameters of
                                   the card(if any).
 -V,--version                      Print version info.
 -ln,--list-named <what>           Print the list of supported named
                                   curves and keys.
 -h,--help                         Print help.
 
 -a,--all                          Test all curve sizes.
 -b,--bit-size <bits>              Set curve size.
 
 -fp,--prime-field                 Use a prime field.
 -f2m,--binary-field               Use a binary field.
 
 -c,--curve <curve_file>           Use curve from file <curve_file>
                                   (field,a,b,gx,gy,r,k).
 -nc,--named-curve <cat/id>        Use a named curve, from CurveDB:
                                   <cat/id>
 -u,--custom                       Use a custom curve (applet-side
                                   embedded, SECG curves).
 -npub,--named-public <cat/id>     Use public key from KeyDB: <cat/id>
 -pub,--public <pubkey_file>       Use public key from file <pubkey_file>
                                   (wx,wy).
 -priv,--private <privkey_file>    Use private key from file
                                   <privkey_file> (s).
 -npriv,--named-private <cat/id>   Use private key from KeyDB: <cat/id>
 -k,--key <key_file>               Use keyPair from file <key_file>
                                   (wx,wy,s).
 -nk,--named-key <cat/id>          Use keyPair from KeyDB: <cat/id>

 -i,--input <input_file>           Input from file <input_file>, for ECDSA
                                   signing.
 -o,--output <output_file>         Output into file <output_file>.
 -l,--log <log_file>               Log output into file [log_file].
 -v,--verbose                      Turn on verbose logging.
    --format <format>              Output format to use. One of:
                                   text,yml,xml.
 -f,--fresh                        Generate fresh keys (set domain
                                   parameters before every generation).
 --cleanup                         Send the cleanup command trigerring
                                   JCSystem.requestObjectDeletion()
                                   after some operations.
 -s,--simulate                     Simulate a card with jcardsim instead
                                   of using a terminal.
 -y,--yes                          Accept all warnings and prompts.
 
 -ka,--ka-type <type>              Set KeyAgreement object [type],
                                   corresponds to JC.KeyAgreement
                                   constants.
 -sig,--sig-type <type>            Set Signature object [type],
                                   corresponds to JC.Signature constants.
 -C,--color                        Print stuff with color, requires ANSI
                                   terminal.
```

### Actions

#### Export
`-e / --export`

Exports the default curves (if any) that are preset on the card.
Use with `-o / --output [out_file]` to output the curve parameters to a file.
For format of this file see [FORMAT](docs/FORMAT.md).

#### Test
`-t / --test [test_suite]`

Perform support,performance and vulnerability tests of ECC.

Use with `-o / --output [out_type:]<out_file>` to output the test results to a file.
For possible formats of this file see [FORMAT](docs/FORMAT.md).
For more info about the test suites see [TESTS](docs/TESTS.md).

#### Generate
`-g / --generate [amount]`

Generates batches of EC keypairs and exports them.
Use with `-o / --output [out_file]` to output the generated keys to a file.
For format of this file see [FORMAT](docs/FORMAT.md).

#### ECDH
`-dh / --ecdh [count]`

Performs ECDH.
Use with `-o / --output [out_file]` to output into a file.
For format of this file see [FORMAT](docs/FORMAT.md).
Respects the KeyAgreement type specified in `-ka / --ka-type [type]`.


#### ECDSA
`-dsa / --ecdsa [count]`

Performs ECDSA.
Useful with `-i / --input [in_file]` to sign the contents of a file.
Use with `-o / --output [out_file]` to output into a file.
For format of these files see [FORMAT](docs/FORMAT.md).
Respects the Signature type specified in `-sig / --sig-type [type]`.

#### List named curves
`-ln / --list-named []`

Lists categories of curves, keys and keypairs embedded in ECTester's jar, along with some information about them.
These can be used as arguments to the `-n[c|k|pub|priv] / --named-[curve|key|public|private]` parameters.

With the format: `category/name`.

For example:
`secg/secp192r1` identifies the SECG 192 bit prime field curve known as `secp192r1`.

For more info about the curves and curve categories see [CURVES](docs/CURVES.md).

### Example

Snippet below shows running the default test suite while simulating(`-s`), so using JCardSim.
This shows that JCardsim simulates 112b Fp support with default curve present and supports ECDH, ECDHC and ECDSA.

    > java -jar ECTesterReader.jar -t -s
    ═══ Running test suite: default ═══
    ═══ The default test suite tests basic support of ECDH and ECDSA.
    ═══ Date: 2018.05.02 20:29:38
    ═══ ECTester version: v0.2.0
    ═══ Card ATR: 3bfa1800008131fe454a434f5033315632333298
     OK ┳ (0) Tests of 112b ALG_EC_FP support.                                                   ┃ SUCCESS   ┃ All sub-tests matched the expected mask.
        ┣  OK ━ Allocate both keypairs 112b ALG_EC_FP                                            ┃ SUCCESS   ┃   22 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ━ Generate both keypairs                                                           ┃ SUCCESS   ┃   23 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ━ Allocate both keypairs 112b ALG_EC_FP                                            ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ━ Set custom curve parameters on both keypairs                                     ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ━ Generate both keypairs                                                           ┃ SUCCESS   ┃    8 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ┳ KeyAgreement tests.                                                              ┃ SUCCESS   ┃ Some sub-tests did have the expected result.
        ┃     ┣  OK ┳ Test of the ALG_EC_SVDP_DH KeyAgreement.                                   ┃ SUCCESS   ┃ Some ECDH is supported.
        ┃     ┃     ┣  OK ━ Allocate KeyAgreement(ALG_EC_SVDP_DH) object                         ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
        ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DH of local pubkey and remote privkey(unchanged point)   ┃ SUCCESS   ┃    2 ms ┃  OK   (0x9000)
        ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DH of local pubkey and remote privkey(COMPRESSED point)  ┃ SUCCESS   ┃    2 ms ┃  OK   (0x9000)
        ┃     ┃     ┗  OK ━ Mean = 1722885 ns, Median = 1718807 ns, Mode = 1614047 ns            ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
        ┃     ┣  OK ┳ Test of the ALG_EC_SVDP_DHC KeyAgreement.                                  ┃ SUCCESS   ┃ Some ECDH is supported.
        ┃     ┃     ┣  OK ━ Allocate KeyAgreement(ALG_EC_SVDP_DHC) object                        ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000)
        ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DHC of local pubkey and remote privkey(unchanged point)  ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
        ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DHC of local pubkey and remote privkey(COMPRESSED point) ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
        ┃     ┃     ┗  OK ━ Mean = 1563980 ns, Median = 1549170 ns, Mode = 1514747 ns            ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
        ┃     ┣ NOK ━ Allocate KeyAgreement(ALG_EC_SVDP_DH_PLAIN) object                         ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┃     ┣ NOK ━ Allocate KeyAgreement(ALG_EC_SVDP_DHC_PLAIN) object                        ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┃     ┣ NOK ━ Allocate KeyAgreement(ALG_EC_PACE_GM) object                               ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┃     ┗ NOK ━ Allocate KeyAgreement(ALG_EC_SVDP_DH_PLAIN_XY) object                      ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┗  OK ┳ Signature tests.                                                                 ┃ SUCCESS   ┃ Some sub-tests did have the expected result.
              ┣  OK ┳ Test of the ALG_ECDSA_SHA signature.                                       ┃ SUCCESS   ┃ All sub-tests had the expected result.
              ┃     ┣  OK ━ Allocate Signature(ALG_ECDSA_SHA) object                             ┃ SUCCESS   ┃    3 ms ┃  OK   (0x9000)
              ┃     ┣  OK ━ ALG_ECDSA_SHA with local keypair(random data)                        ┃ SUCCESS   ┃   14 ms ┃  OK   (0x9000)
              ┃     ┣  OK ━ Sign (Mean = 1890914 ns, Median = 1500125 ns, Mode = 1422588 ns)     ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
              ┃     ┗  OK ━ Verify (Mean = 1873952 ns, Median = 1870348 ns, Mode = 1843902 ns)   ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
              ┣ NOK ━ Allocate Signature(ALG_ECDSA_SHA_224) object                               ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
              ┣ NOK ━ Allocate Signature(ALG_ECDSA_SHA_256) object                               ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
              ┣ NOK ━ Allocate Signature(ALG_ECDSA_SHA_384) object                               ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
              ┗ NOK ━ Allocate Signature(ALG_ECDSA_SHA_512) object                               ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)

#### Legend
 - Some general information about the test suite and card is output first, test data follows after.
 - The **OK**/**NOK** values on the left represent the complete evaluated result of a test, as a test can be expected
   to succeed or fail, this is different than the values on the right:
   - **SUCCESS**: Is **OK**, the test was expected to pass and it did.
   - **FAILURE**: Is **NOK**, the test was expected to pass, but it did not.
   - **UXSUCCESS**: Is **NOK**, the test was expected to fail, but it did not.
   - **XFAILURE**: Is **OK**, the test was expected to fail, and it did.
   - **ERROR**: Is **NOK** an unexpected error during testing arose.
 - The tests can be compounded into compound tests, which are visible as a tree of tests and sub-tests.
 - The duration of non-compound tests is shown in the third column, this is a rough estimate, measured from before the APDU is sent, to just after the response is received.
 - The cause of the test result, is shown in the last column, for non-compound tests, these are JavaCard(or custom) status words, from operations done on the card.

If you are interested in testing support for other JavaCard algorithms, please visit JCAlgTester project: https://github.com/crocs-muni/JCAlgTest


## Standalone library testing

Currently supported libraries include:
 - BouncyCastle
 - SunEC
 - OpenSSL
 - Crypto++
 - libtomcrypt
 - botan
 - Microsoft CNG
 
For more information on ECC libraries see [LIBS](docs/LIBS.md).

### Setup

OpenJDK JRE is required to test ECDH on Windows properly, as  Oracle JRE requires the Java Cryptography Providers
for certain classes (such as a [KeyAgreement](https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyAgreement.html)) 
to be signed by keys that are signed by their JCA Code Signing Authority. ECTester internally uses Java Cryptography Provider
API to expose and test native libraries. OpenJDK for Windows can be obtained from [ojdkbuild/ojdkbuild](https://github.com/ojdkbuild/ojdkbuild).

Installing the Java Cryptography Extension Unlimited Strength policy files is necessary to do testing
with quite a lot of practical key sizes, they are available for download:

 - [Java 6](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)
 - [Java 7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
 - [Java 8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)

To install, place them in `${java.home}/jre/lib/security/`.

### Options

```
usage: ECTesterStandalone.jar [-V] [-h] [-C]
 [ (ecdh [-b <n>] [-nc <cat/id>] [-cn <name>] [-t <type>] [--key-type <algorithm>] [-n <amount>]) |
   (ecdsa [-b <n>] [-nc <cat/id>] [-cn <name>] [-t <type>] [-n <amount>] [-f <file>]) |
   (export [-b <n>] [-t <type>]) |
   (generate [-b <n>] [-nc <cat/id>] [-cn <name>] [-n <amount>] [-t <type>]) |
   (list-data [what]) |
   (list-libs) |
   (list-suites) |
   (test [-b <n>] [-nc <cat/id>] [-cn <name>] [-gt <type>] [-kt <type>] [-st <type>] [-f <format>] [--key-type <algorithm>]
         <test-suite>) ]
 [lib]

 ecdh:    | Perform EC based KeyAgreement. |
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
   -cn,--curve-name <name>      Use a named curve, search from curves
                                supported by the library: <name>
   -t,--type <type>             Set KeyAgreement object [type].
      --key-type <algorithm>    Set the key [algorithm] for which the key
                                should be derived in KeyAgreements with
                                KDF. Default is "AES".
   -n,--amount <amount>         Do ECDH [amount] times.

 ecdsa:    | Perform EC based Signature. |
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
   -cn,--curve-name <name>      Use a named curve, search from curves
                                supported by the library: <name>
   -t,--type <type>             Set Signature object [type].
   -n,--amount <amount>         Do ECDSA [amount] times.
   -f,--file <file>             Input [file] to sign.

 export:    | Export default curve parameters. |
   -b,--bits <n>                What size of curve to use.
   -t,--type <type>             Set KeyPair object [type].

 generate:    | Generate EC keypairs. |
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
   -cn,--curve-name <name>      Use a named curve, search from curves
                                supported by the library: <name>
   -n,--amount <amount>         Generate [amount] of EC keys.
   -t,--type <type>             Set KeyPairGenerator object [type].

 list-data:    | List/show contained EC domain parameters/keys. |
   [what]                       what to list.

 list-libs:    | List supported libraries. |

 list-suites:    | List supported test suites. |

 test:    | Test a library. |
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
   -cn,--curve-name <name>      Use a named curve, search from curves
                                supported by the library: <name>
   -gt,--kpg-type <type>        Set the KeyPairGenerator object [type].
   -kt,--ka-type <type>         Set the KeyAgreement object [type].
   -st,--sig-type <type>        Set the Signature object [type].
   -f,--format <format>         Set the output format, one of
                                text,yaml,xml.
      --key-type <algorithm>    Set the key [algorithm] for which the key
                                should be derived in KeyAgreements with
                                KDF. Default is "AES".
   <test-suite>                 The test suite to run.
```

