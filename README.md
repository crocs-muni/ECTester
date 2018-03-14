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
- Behavior of card when invalid curves/points are provided (should fail)

See `java -jar ECTesterReader.jar -h` for more.

### Options

```
 -dsa,--ecdsa <count>              Sign data with ECDSA, [count] times.
 -t,--test <test_suite>            Test ECC support. [test_suite]:
                                   - default:
                                   - invalid:
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
 -s,--simulate                     Simulate a card with jcardsim instead
                                   of using a terminal.
 -y,--yes                          Accept all warnings and prompts.
 
 -ka,--ka-type <type>              Set KeyAgreement object [type],
                                   corresponds to JC.KeyAgreement
                                   constants.
 -sig,--sig-type <type>            Set Signature object [type],
                                   corresponds to JC.Signature constants.
```

### Actions

#### Export
`-e / --export`

Exports the default curves (if any) that are preset on the card.
Use with `-o / --output [out_file]` to output the curve parameters to a file.
For format of this file see [FORMAT](docs/FORMAT.md).

#### Test
`-t / --test [test_suite]`

Perform support and performance tests of ECC.

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
    ═══ The default test suite run basic support of ECDH and ECDSA.
    ═══ Card ATR: 3bfa1800008131fe454a434f5033315632333298
    NOK ┳ Tests of 112b ALG_EC_FP support. Some.                                               ┃ FAILURE   ┃ Some sub-tests did not have the expected result.
        ┣  OK ━ Allocated both keypairs 112b ALG_EC_FP                                         ┃ SUCCESS   ┃   50 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ━ Generated both keypairs                                                        ┃ SUCCESS   ┃   37 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ━ Set custom curve parameters on both keypairs                                   ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ━ Generated both keypairs                                                        ┃ SUCCESS   ┃   16 ms ┃  OK   (0x9000) OK   (0x9000)
        ┣  OK ┳ Test of the ALG_EC_SVDP_DH KeyAgreement.                                       ┃ SUCCESS   ┃ All sub-tests had the expected result.
        ┃     ┣  OK ━ Allocated KeyAgreement(ALG_EC_SVDP_DH) object                            ┃ SUCCESS   ┃    2 ms ┃  OK   (0x9000)
        ┃     ┣  OK ━ ALG_EC_SVDP_DH of local pubkey and remote privkey(unchanged point)       ┃ SUCCESS   ┃    7 ms ┃  OK   (0x9000)
        ┃     ┗  OK ━ ALG_EC_SVDP_DH of local pubkey and remote privkey(COMPRESSED point)      ┃ SUCCESS   ┃   14 ms ┃  OK   (0x9000)
        ┣  OK ┳ Test of the ALG_EC_SVDP_DHC KeyAgreement.                                      ┃ SUCCESS   ┃ All sub-tests had the expected result.
        ┃     ┣  OK ━ Allocated KeyAgreement(ALG_EC_SVDP_DHC) object                           ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000)
        ┃     ┣  OK ━ ALG_EC_SVDP_DHC of local pubkey and remote privkey(unchanged point)      ┃ SUCCESS   ┃    3 ms ┃  OK   (0x9000)
        ┃     ┗  OK ━ ALG_EC_SVDP_DHC of local pubkey and remote privkey(COMPRESSED point)     ┃ SUCCESS   ┃    5 ms ┃  OK   (0x9000)
        ┣ NOK ━ Allocated KeyAgreement(ALG_EC_SVDP_DH_PLAIN) object                            ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┣ NOK ━ Allocated KeyAgreement(ALG_EC_SVDP_DHC_PLAIN) object                           ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┣ NOK ━ Allocated KeyAgreement(ALG_EC_PACE_GM) object                                  ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┣ NOK ━ Allocated KeyAgreement(ALG_EC_SVDP_DH_PLAIN_XY) object                         ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┣  OK ┳ Test of the ALG_ECDSA_SHA signature.                                           ┃ SUCCESS   ┃ All sub-tests had the expected result.
        ┃     ┣  OK ━ Allocated Signature(ALG_ECDSA_SHA) object                                ┃ SUCCESS   ┃    7 ms ┃  OK   (0x9000)
        ┃     ┗  OK ━ ALG_ECDSA_SHA with local keypair(random data)                            ┃ SUCCESS   ┃   43 ms ┃  OK   (0x9000)
        ┣ NOK ━ Allocated Signature(ALG_ECDSA_SHA_224) object                                  ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┣ NOK ━ Allocated Signature(ALG_ECDSA_SHA_256) object                                  ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┣ NOK ━ Allocated Signature(ALG_ECDSA_SHA_384) object                                  ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
        ┗ NOK ━ Allocated Signature(ALG_ECDSA_SHA_512) object                                  ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)

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
 - libtomcrypt
 - botan
 
For more information on ECC libraries see [LIBS](docs/LIBS.md).

### Setup

Installing the Java Cryptography Extension Unlimited Strength policy files is necessary to do testing
with quite a lot of practical key sizes, they are available for download:

 * [Java 6](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)
 * [Java 7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
 * [Java 8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)

To install, place them in `${java.home}/jre/lib/security/`.

### Options

```
usage: ECTesterStandalone.jar [-V] [-h] [ (ecdh [-t <type>] [-n <amount>] [-b <n>] [-nc <cat/id>]) |
(ecdsa [-t <type>] [-n <amount>] [-b <n>] [-nc <cat/id>] [-f <file>]) |
(export [-t <type>] [-b <n>]) | (generate [-nc <cat/id>] [-n <amount>] [-t
<type>] [-b <n>]) | (list-data  [what]) | (list-libs) | (test [-gt <type>]
[-kt <type>] [-st <type>] [-b <n>] [-nc <cat/id>]) ] [lib]

  -V,--version   Print version info.
  -h,--help      Print help.
  [lib]   What library to use.

 ecdh:
   -t,--type <type>             Set KeyAgreement object [type].
   -n,--amount <amount>         Do ECDH [amount] times.
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>

 ecdsa:
   -t,--type <type>             Set Signature object [type].
   -n,--amount <amount>         Do ECDSA [amount] times.
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
   -f,--file <file>             Input [file] to sign.

 export:
   -t,--type <type>   Set KeyPair object [type].
   -b,--bits <n>      What size of curve to use.

 generate:
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
   -n,--amount <amount>         Generate [amount] of EC keys.
   -t,--type <type>             Set KeyPairGenerator object [type].
   -b,--bits <n>                What size of curve to use.

 list-data:
   [what]   what to list.

 list-libs:

 test:
   -gt,--kpg-type <type>        Set the KeyPairGenerator object [type].
   -kt,--ka-type <type>         Set the KeyAgreement object [type].
   -st,--sig-type <type>        Set the Signature object [type].
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
```

