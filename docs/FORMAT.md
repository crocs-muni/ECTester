# Format
ECTester mostly reads/outputs data in either human-readable format or using CSV, YAML or XML, depending on the data.

## Test runs
By default test runs are output in a human readable format, however YAML and XML is also supported and can be selected
by using the `--format` option. Also, prefixing the output file name when using the `-o/--output` option allows to output
the same test run in different formats to different files.

For example:
`--format yaml -o default_output.yaml -o xml:output_file.xml -o text:readable_text_file.txt `

The YAML output of the test runs is used to generate the static pages of the tests at <https://crocs-muni.github.io/ECTester/>.

## Notation
In the rest of this documentation the following notation is used

 - `p` - prime F_p
 - `m` - binary field exponent F_2^m
   - `e1` - largest exponent of the field polynomial
   - `e2` - middle exponenet of the field polynomial, or `0000` if field poly is a trinomial
   - `e3` - smallest exponent (except zero) of the field polynomial, or `0000` if field poly is a trinomial
 - `a` - a parameter in short Weierstrass curve equation
 - `b` - b parameter in short Weierstrass curve equation
 - `gx` - x coordinate of the curve base-point g
 - `gy` - y coordinate of the curve base-point g
 - `n` - the base-point order
 - `h` - the base-point cofactor
 - `wx` - the x coordinate of the public key
 - `wy` - the y coordinate of th public key
 - `s` - the private key value

## Curves
Input files for the `-c/--curve` option should be in CSV, little-endian hexadecimal format.
Output of the `-e/--export` option will also be in this format.

### Prime field
`p,a,b,gx,gy,n,h`

### Binary field
`m,e1,e2,e3,a,b,gx,gy,n,h`

## Key material
Input files for the `-k/--key`, `-pub/--public` and `-priv/--private` options should be in CSV, little-endian hexadecimal format.

### Keypair
`wx,wy,s`

### Public key
`wx,wy`

### Private key
`s`

## Key generation output(CSV)
Output of the `-g/--generate` option.

For ECTesterReader this has the format:

`index;genTime[milli];exportTime[milli];pubW;privS` where `pubW` is the public key used in ANSI X9.62 format,
`privS` is the private key, `genTime` is the time required to generate the keypair and `exportTime` is the time required to export it (recover it from the JavaCard API and send it to the reader).

For ECTesterStandalone this has the format:

`index;time[nano];pubW;privS`

The string in the brackets denotes the measurement unit used, can be one of `milli`, `micro`, `nano` and also `instr` for ECTesterStandalone, if the measured duration is instructions.

## KeyAgreement output(CSV)
Output of the `-dh/--ecdh` option.

For ECTesterReader this has the format:

`index;time[milli];pubW;privS;secret[SHA1]` where `pubW` is the public key used in ANSI X9.62 format, `privS` is the private key
and `secret` is the KeyAgreement result. The value in brackets denotes what hash algorithm was used, can be `NONE`.

For ECTesterStandalone this has the format:

`index;time[nano];pubW;privS;secret[SHA1]` and the same meaning as for ECTesterReader.

The string in the brackets denotes the measurement unit used, can be one of `milli`, `micro`, `nano` and also `instr` for ECTesterStandalone, if the measured duration is instructions.

## Signature output(CSV)
Output of the `-dsa/--ecdsa` option.

For ECTesterReader this has the format:

`index;signTime[milli];verifyTime[milli];data;pubW;privS;signature[SHA1];nonce;valid` where `pubW` is the public key used
in ANSI X9.62 format, `privS` is the private key, `signTime` and `verifyTime` are the durations of the sign and verify operations,
`data` is the signed data (if available), `signature` is the produced signature, `nonce` is the `k` (nonce) value recovered from the signature
abd the private key (if possible), `valid` denotes the verification result. The value in brackets after `signature` denotes what hash algorithm was used, can be `NONE`.

For ECTesterStandalone this has the format:

 `index;signTime[nano];verifyTime[nano];data;pubW;privS;signature[SHA1];nonce;verified` and the same meaning as for ECTesterReader.

The string in the brackets denotes the measurement unit used, can be one of `milli`, `micro`, `nano` and also `instr` for ECTesterStandalone, if the measured duration is instructions.