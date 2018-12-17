# ECTester
[![Build status](https://api.travis-ci.org/crocs-muni/ECTester.svg?branch=master)](https://travis-ci.org/crocs-muni/ECTester) [![Build status](https://ci.appveyor.com/api/projects/status/02kcaf52op89910u?svg=true)](https://ci.appveyor.com/project/J08nY/ectester-cm6ng) [![GitHub release](https://img.shields.io/github/release/crocs-muni/ECTEster.svg)](https://github.com/crocs-muni/ECTester/releases)  [![license](https://img.shields.io/github/license/crocs-muni/ECTester.svg)](https://github.com/crocs-muni/ECTester/blob/master/LICENSE) [![docs](https://img.shields.io/badge/docs-github.io-brightgreen.svg)](https://crocs-muni.github.io/ECTester/)

Tests support and behavior of elliptic curve cryptography implementations on JavaCards (`TYPE_EC_FP` and `TYPE_EC_F2M`) and on selected software libraries.
For more information on ECC support on JavaCards see the [github page](https://crocs-muni.github.io/ECTester/), with results, tables and docs.

## Setup

ECTester uses ant. There are three parts of ECTester, the JavaCard applet used for testing, the reader app which controls it and the standalone app which tests software libraries.
```bash
git submodule update --init --recursive       # To initialize submodules.
ant -f build-reader.xml package               # To build the reader tool (jar) -> "dist/ECTesterReader.jar"
ant -f build-standalone.xml package           # To build the standalone tool (jar) -> "dist/ECTesterStandalone.jar"
ant -f build-applet.xml build                 # To build the applet (cap) -> "applet/ectester.cap".
```
Build produces both a lightweight version of the JARs and a full version of the JARs with dependencies included, the latter has the `*-dist.jar` suffix.
The standalone build tries building test binaries for all the supported libraries, and silently fails if the library is not properly supported.

The applet comes in two flavors, targeting JavaCard 2.2.1 and 2.2.2. The 2.2.2 version supports extended length APDUs which are necessary for some commands
to work properly. Use the `cap` ant property to specify which CAP file to build, either `ectester221.cap` or `ectester222.cap`.

To build the 221 version do:
```bash
ant -f build-applet.xml build -Dcap=ectester221.cap
```

## JavaCard testing

1. Upload `applet/ectester.cap` using your favorite tool (e.g., [GlobalPlatformPro tool](https://github.com/martinpaljak/GlobalPlatform)) or the `build-applet.xml` ant file.
2. Run `java -jar dist/ECTesterReader.jar -t`.
3. Inspect output log with annotated results.

Following operations are tested in the default suite:
- Allocation of new KeyPair class for specified parameters
- Generation of KeyPair with default curve
- Setting of custom curve and KeyPair generation
- Generation of shared secret via ECDH
- Signature via ECDSA

See `java -jar ECTesterReader.jar -h`, `java -jar ECTesterReader.jar -ls` and [DOCS](docs/TESTS.md) for more.

### Options

```
 -V,--version                         Print version info.
 -h,--help                            Print help.
 -ln,--list-named <what>              Print the list of supported named
                                      curves and keys.
 -ls,--list-suites                    List supported test suites.
 -e,--export                          Export the defaut curve parameters
                                      of the card(if any).
 -g,--generate <amount>               Generate <amount> of EC keys.
 -t,--test <test_suite[:from[:to]]>   Test ECC support. Optionally specify
                                      a test number to run only a part of
                                      a test suite. <test_suite>:
                                      - default:
                                      - compression:
                                      - invalid:
                                      - twist:
                                      - degenerate:
                                      - cofactor:
                                      - wrong:
                                      - signature:
                                      - composite:
                                      - test-vectors:
                                      - edge-cases:
                                      - miscellaneous:
 -dh,--ecdh <count>                   Do EC KeyAgreement (ECDH...),
                                      [count] times.
 -dsa,--ecdsa <count>                 Sign data with ECDSA, [count] times.
 -nf,--info                           Get applet info.
 -b,--bit-size <bits>                 Set curve size.
 -fp,--prime-field                    Use a prime field.
 -f2m,--binary-field                  Use a binary field.
 -nc,--named-curve <cat/id>           Use a named curve, from CurveDB:
                                      <cat/id>
 -c,--curve <curve_file>              Use curve from file <curve_file>
                                      (field,a,b,gx,gy,r,k).
 -u,--custom                          Use a custom curve (applet-side
                                      embedded, SECG curves).
 -npub,--named-public <cat/id>        Use public key from KeyDB: <cat/id>
 -pub,--public <pubkey_file>          Use public key from file
                                      <pubkey_file> (wx,wy).
 -npriv,--named-private <cat/id>      Use private key from KeyDB: <cat/id>
 -priv,--private <privkey_file>       Use private key from file
                                      <privkey_file> (s).
 -nk,--named-key <cat/id>             Use keyPair from KeyDB: <cat/id>
 -k,--key <key_file>                  Use keyPair from file <key_file>
                                      (wx,wy,s).
 -i,--input <input_file>              Input from file <input_file>, for
                                      ECDSA signing.
 -o,--output <output_file>            Output into file <output_file>. The
                                      file can be prefixed by the format
                                      (one of text,yml,xml), such as:
                                      xml:<output_file>.
 -l,--log <log_file>                  Log output into file [log_file].
 -v,--verbose                         Turn on verbose logging.
    --format <format>                 Output format to use. One of:
                                      text,yml,xml.
    --fixed                           Generate key(s) only once, keep them
                                      for later operations.
    --fixed-private                   Generate private key only once, keep
                                      it for later ECDH.
    --fixed-public                    Generate public key only once, keep
                                      it for later ECDH.
 -f,--fresh                           Generate fresh keys (set domain
                                      parameters before every generation).
    --time                            Output better timing values, by
                                      running command in dry run mode and
                                      normal mode, and subtracting the
                                      two.
    --cleanup                         Send the cleanup command trigerring
                                      JCSystem.requestObjectDeletion()
                                      after some operations.
 -s,--simulate                        Simulate a card with jcardsim
                                      instead of using a terminal.
 -y,--yes                             Accept all warnings and prompts.
 -ka,--ka-type <type>                 Set KeyAgreement object [type],
                                      corresponds to JC.KeyAgreement
                                      constants.
 -sig,--sig-type <type>               Set Signature object [type],
                                      corresponds to JC.Signature
                                      constants.
 -C,--color                           Print stuff with color, requires
                                      ANSI terminal.
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

To select which tests will be performed, it is possible to enter the test suite name with a suffix
which specifies the number of the first test to be run, and optionally the number of the last test to be run as `-t <test_suite>[:start_index[:stop_index]]`.

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

#### List test suites
`-ls / --list-suites`

Lists the implemented test suites and gives their short description.

#### Get applet info
`-nf / --info`

Get and print ECTester applet info from an applet installed on a card.

Outputs:

 - ECTester applet version
 - ECTester APDU support
 - JavaCard API version
 - JavaCard cleanup support

### Example

Snippet below shows running the default test suite while simulating(`-s`), so using JCardSim.
This shows that JCardsim simulates 112b Fp support with default curve present and supports ECDH, ECDHC and ECDSA.

```
> java -jar ECTesterReader.jar -t -s
═══ Running test suite: default ═══
═══ The default test suite tests basic support of ECDH and ECDSA.
═══ Date: 2018.05.02 20:29:38
═══ ECTester version: v0.3.0
═══ Card ATR: 3bfa1800008131fe454a434f5033315632333298
■━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┓
 OK ╋ (0) Get applet info: v0.3.0; 3.0; basic                                                             ┃ SUCCESS   ┃ All sub-tests had the expected result.
    ┗  OK ━ Get applet info                                                                               ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000)
■━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┓
 OK ╋ (1) Tests of 112b ALG_EC_FP support.                                                                ┃ SUCCESS   ┃ All sub-tests matched the expected mask.
    ┣  OK ━ Allocate both keypairs 112b ALG_EC_FP                                                         ┃ SUCCESS   ┃  166 ms ┃  OK   (0x9000) OK   (0x9000)
    ┣  OK ━ Generate both keypairs                                                                        ┃ SUCCESS   ┃   19 ms ┃  OK   (0x9000) OK   (0x9000)
    ┣  OK ━ Allocate both keypairs 112b ALG_EC_FP                                                         ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000) OK   (0x9000)
    ┣  OK ━ Set custom curve parameters on both keypairs                                                  ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000) OK   (0x9000)
    ┣  OK ━ Generate both keypairs                                                                        ┃ SUCCESS   ┃    5 ms ┃  OK   (0x9000) OK   (0x9000)
    ┣  OK ┳ KeyAgreement tests.                                                                           ┃ SUCCESS   ┃ Some sub-tests did have the expected result.
    ┃     ┣  OK ┳ Test of the ALG_EC_SVDP_DH KeyAgreement.                                                ┃ SUCCESS   ┃ Some ECDH is supported.
    ┃     ┃     ┣  OK ━ Allocate KeyAgreement(ALG_EC_SVDP_DH) object                                      ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
    ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DH of local pubkey and remote privkey                                 ┃ SUCCESS   ┃    2 ms ┃  OK   (0x9000)
    ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DH of local pubkey and remote privkey(COMPRESSED point)               ┃ SUCCESS   ┃    3 ms ┃  OK   (0x9000)
    ┃     ┃     ┗  OK ━ Mean = 1879950 ns, Median = 1835076 ns, Mode = 1763287 ns                         ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
    ┃     ┣  OK ┳ Test of the ALG_EC_SVDP_DHC KeyAgreement.                                               ┃ SUCCESS   ┃ Some ECDH is supported.
    ┃     ┃     ┣  OK ━ Allocate KeyAgreement(ALG_EC_SVDP_DHC) object                                     ┃ SUCCESS   ┃    0 ms ┃  OK   (0x9000)
    ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DHC of local pubkey and remote privkey                                ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
    ┃     ┃     ┣  OK ━ ALG_EC_SVDP_DHC of local pubkey and remote privkey(COMPRESSED point)              ┃ SUCCESS   ┃    2 ms ┃  OK   (0x9000)
    ┃     ┃     ┗  OK ━ Mean = 1748499 ns, Median = 1760792 ns, Mode = 1647372 ns                         ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
    ┃     ┣ NOK ━ Allocate KeyAgreement(ALG_EC_SVDP_DH_PLAIN) object                                      ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
    ┃     ┣ NOK ━ Allocate KeyAgreement(ALG_EC_SVDP_DHC_PLAIN) object                                     ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
    ┃     ┣ NOK ━ Allocate KeyAgreement(ALG_EC_PACE_GM) object                                            ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
    ┃     ┗ NOK ━ Allocate KeyAgreement(ALG_EC_SVDP_DH_PLAIN_XY) object                                   ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
    ┗  OK ┳ Signature tests.                                                                              ┃ SUCCESS   ┃ Some sub-tests did have the expected result.
          ┣  OK ┳ Test of the ALG_ECDSA_SHA signature.                                                    ┃ SUCCESS   ┃ All sub-tests had the expected result.
          ┃     ┣  OK ━ Allocate Signature(ALG_ECDSA_SHA) object                                          ┃ SUCCESS   ┃    2 ms ┃  OK   (0x9000)
          ┃     ┣  OK ━ ALG_ECDSA_SHA with local keypair(random data)                                     ┃ SUCCESS   ┃   17 ms ┃  OK   (0x9000)
          ┃     ┣  OK ━ Sign (Mean = 1451086 ns, Median = 1413292 ns, Mode = 1378296 ns)                  ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
          ┃     ┗  OK ━ Verify (Mean = 1850022 ns, Median = 1837022 ns, Mode = 1744613 ns)                ┃ SUCCESS   ┃    1 ms ┃  OK   (0x9000)
          ┣ NOK ━ Allocate Signature(ALG_ECDSA_SHA_224) object                                            ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
          ┣ NOK ━ Allocate Signature(ALG_ECDSA_SHA_256) object                                            ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
          ┣ NOK ━ Allocate Signature(ALG_ECDSA_SHA_384) object                                            ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
          ┗ NOK ━ Allocate Signature(ALG_ECDSA_SHA_512) object                                            ┃ FAILURE   ┃    0 ms ┃  fail (NO_SUCH_ALG, 0x0003)
```

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
 - [BouncyCastle](https://bouncycastle.org/java.html)
 - [Sun EC](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunEC)
 - [OpenSSL](https://www.openssl.org/)
 - [BoringSSL](https://boringssl.googlesource.com/boringssl)
 - [wolfSSL](https://www.wolfssl.com/)
 - [Crypto++](https://cryptopp.com/)
 - [libtomcrypt](http://www.libtom.net/LibTomCrypt/)
 - [libgcrypt](https://www.gnupg.org/related_software/libgcrypt/)
 - [Botan](https://botan.randombit.net/)
 - [Microsoft CNG](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx)
 
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
usage: ECTesterStandalone.jar [-V] [-h <command>] [-C] [
(ecdh [-b <n>] [-nc <cat/id>] [-cn <name>] [-o <output_file>] [-t <type>] [--key-type <algorithm>] [-n <amount>]
      [-npriv <cat/id>] [--fixed-private] [-npub <cat/id>] [--fixed-public]) |
(ecdsa [-b <n>] [-nc <cat/id>] [-cn <name>] [-o <output_file>] [-npriv <cat/id>] [-npub <cat/id>] [-t <type>]
      [-n <amount>] [-f <file>]) |
(export [-b <n>] [-o <output_file>] [-t <type>]) |
(generate [-b <n>] [-nc <cat/id>] [-cn <name>] [-o <output_file>] [-n <amount>] [-t <type>]) |
(list-data  [what]) |
(list-libs) |
(list-suites) |
(test [-b <n>] [-nc <cat/id>] [-cn <name>] [-gt <type>] [-kt <type>] [-st <type>] [-f <format>] [--key-type <algorithm>]  <test-suite>) ]
[lib]

  -V,--version          Print version info.
  -h,--help <command>   Print help(about <command>).
  -C,--color            Print stuff with color, requires ANSI terminal.
  [lib]   What library to use.

 ecdh:                               | Perform EC based KeyAgreement. |
   -b,--bits <n>                     What size of curve to use.
   -nc,--named-curve <cat/id>        Use a named curve, from CurveDB:
                                     <cat/id>
   -cn,--curve-name <name>           Use a named curve, search from curves
                                     supported by the library: <name>
   -o,--output <output_file>         Output into file <output_file>.
   -t,--type <type>                  Set KeyAgreement object [type].
      --key-type <algorithm>         Set the key [algorithm] for which the
                                     key should be derived in
                                     KeyAgreements with KDF. Default is
                                     "AES".
   -n,--amount <amount>              Do ECDH [amount] times.
   -npriv,--named-private <cat/id>   Use a named private key, from
                                     CurveDB: <cat/id>
      --fixed-private                Perform ECDH with fixed private key.
   -npub,--named-public <cat/id>     Use a named public key, from CurveDB:
                                     <cat/id>
      --fixed-public                 Perform ECDH with fixed public key.

 ecdsa:                              | Perform EC based Signature. |
   -b,--bits <n>                     What size of curve to use.
   -nc,--named-curve <cat/id>        Use a named curve, from CurveDB:
                                     <cat/id>
   -cn,--curve-name <name>           Use a named curve, search from curves
                                     supported by the library: <name>
   -o,--output <output_file>         Output into file <output_file>.
   -npriv,--named-private <cat/id>   Use a named private key, from
                                     CurveDB: <cat/id>
   -npub,--named-public <cat/id>     Use a named public key, from CurveDB:
                                     <cat/id>
   -t,--type <type>                  Set Signature object [type].
   -n,--amount <amount>              Do ECDSA [amount] times.
   -f,--file <file>                  Input [file] to sign.

 export:                        | Export default curve parameters. |
   -b,--bits <n>                What size of curve to use.
   -o,--output <output_file>    Output into file <output_file>.
   -t,--type <type>             Set KeyPair object [type].

 generate:                      | Generate EC keypairs. |
   -b,--bits <n>                What size of curve to use.
   -nc,--named-curve <cat/id>   Use a named curve, from CurveDB: <cat/id>
   -cn,--curve-name <name>      Use a named curve, search from curves
                                supported by the library: <name>
   -o,--output <output_file>    Output into file <output_file>.
   -n,--amount <amount>         Generate [amount] of EC keys.
   -t,--type <type>             Set KeyPairGenerator object [type].

 list-data:                     | List/show contained EC domain parameters/keys. |
   [what]   what to list.

 list-libs:                     | List supported libraries. |

 list-suites:                   | List supported test suites. |

 test:                          | Test a library. |
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
   <test-suite>   The test suite to run.
```

