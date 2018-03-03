# Format
ECTester mostly reads/outputs data in either human-readable format or using CSV.

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

### Notation
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

## Key generation output(CSV)
Output of the `-g/--generate` option.

`index;time;pubW;privS`

## KeyAgreement output(CSV)
Output of the `-dh/--ecdh` option.

`index;time;pubW;privS;secret`

## Signature output(CSV)
Output of the `-dsa/--ecdsa` option.

`index;time;signature`

## Test runs
By default test runs are output in a human readable format, however YAML and XML is also supported and can be selected
by using the `--format` option. Also, prefixing the output file name when using the `-o/--output` option allows to output 
the same test run in different formats to different files.

For example:
`--format yaml -o default_output.yaml -o xml:output_file.xml -o text:readable_text_file.txt `
