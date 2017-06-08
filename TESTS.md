# Tests

 - `default`
 - `test-vectors`
 - `wrong`
 - `nonprime`
 - `invalid`
 
**NOTE: The `wrong`, `nonprime` and `invalid` test suites caused temporary DoS of some cards. These test suites prompt you for
confirmation before running, be cautious.**

## Default
Tests the default curves present on the card. These might not be present or the card might not even support ECC.
Tests keypair allocation, generation, ECDH and ECDSA. ECDH is first tested with two valid generated keypairs, then a with a
public key that is corrupted in various ways, these tests should fail.

This test suite is run if no argument is provided to `-t / --test`.

Supports the `-nc / --named-curve` option so you can specify a category of curves or a curve to use if the card doesn't
have default curves preset.

For example:
```bash
java -jar ECTester.jar -nc secg -a -fp -t
```
tests all(`-a`), prime field(`-fp`) SECG curves, using the default test suite.

```bash
java -jar ECTester.jar -u -a -f2m -t
```
tests all(`-a`), binary field(`-f2m`), custom(`-u`) curves.

```bash
java -jar ECTester.jar -b 128 -fp -t
```
tests a 128 bit(`-b`), prime field(`-fp`) curve, (if a default one is present).

## Test-Vectors
Tests using known test vectors provided by NIST/SECG/Brainpool:

[SECG - GEC2](http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf)

[NIST - ECCDH](http://csrc.nist.gov/groups/STM/cavp/component-testing.html#ECCCDH)

[Brainpool - RFC6931](https://tools.ietf.org/html/rfc6932#appendix-A.1)

[Brainpool - RFC7027](https://tools.ietf.org/html/rfc7027#appendix-A)

For example:
```bash
java -jar ECTester.jar -t test-vectors -nc nist -a -f2m
```
tests all(`-a`), binary field(`-f2m`) NIST curves for which test-vectors are provided. Although this test suite is better for general testing:
```bash
java -jar ECTester.jar -t test-vectors -a
```
## Wrong
Tests using the default tests on a category of wrong curves. These curves are not really curves as they have:
 - non-prime field in the prime-field case
 - reducible polynomial as the field polynomial in the binary case

These tests should fail generally. They are equivalent with `java -jar ECTester.jar -nc wrong -t`, the default tests over the `wrong` category
of curves.
 
For example:
```bash
java -jar ECTester.jar -t wrong -b 521 -fp
```
tests a 521 bit(`-b`), prime-field(`-fp`) wrong curve.

## Nonprime
Tests using curves that don't have a prime order/nearly prime order.
These tests should generally fail, a success here implies the card **WILL** use a non-secure curve if such curve is set
by the applet. Operations over such curves are susceptible to small-subgroup attacks.

For example:
```bash
java -jar ECTester.jar -t nonprime -b 160 -fp
```

## Invalid
Tests using known named curves from several categories(SECG/NIST/Brainpool) against pregenerated *invalid* public keys.
These tests should definitely fail, a success here implies the card is susceptible to invalid curve attacks.


For example:
```bash
java -jar ECTester.jar -t invalid -nc nist -a -fp
```
tests using all(`-a`), prime-field(`-fp`) NIST curves and pregenerated *invalid* public keys for these curves.