# Test suites

 - `default`
 - `test-vectors`
 - `compression`
 - `miscellaneous`
 - `signature`
 - `wrong`*
 - `invalid`*
 - `twist`*
 - `degenerate`*
 - `composite`*
 - `cofactor`*
 - `edge-cases`*

**\*NOTE: The `wrong`, `composite`, `invalid`,`twist`, `cofactor`, `edge-cases` and `degenerate` test suites caused temporary/permanent DoS of some cards. These test suites prompt you for
confirmation before running, be cautious.**

## Default
Tests support for ECC and the presence of default curves on the target. These might not be present or the target might not even support ECC.
Tests keypair allocation, generation, ECDH and ECDSA. ECDH is first tested with two valid generated keypairs, then
with a compressed public key to test support for compressed points.

This test suite is run if no argument is provided to `-t / --test`.


## Test-Vectors
Tests ECDH using known test vectors provided by NIST/SECG/Brainpool:

[SECG - GEC2](http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf)

[NIST - ECCDH](http://csrc.nist.gov/groups/STM/cavp/component-testing.html#ECCCDH)

[Brainpool - RFC6931](https://tools.ietf.org/html/rfc6932#appendix-A.1)

[Brainpool - RFC7027](https://tools.ietf.org/html/rfc7027#appendix-A)


## Compression
Tests support for compression of public points in ECDH as specified in ANSI X9.62. The standard specifies two forms of point compression,
fully compressed point contains the `x` coordinate and one bit of the `y` coordinate, from which the whole point can be reconstructed, hybrid form
of a compressed point contains both the `x` and `y` coordinates but also one bit of the `y` coordinate.

Tests ECDH with points in compressed and hybrid form. Also tests target response to a hybrid point with wrong `y` coordinate and to the point at infinity(as public key in ECDH).
Tests ECDH with invalid compressed point, where `x` does not lie on the curve.

   - Compressed form, valid
   - Hybrid form, valid
   - Hybrid form, invalid `y`
   - Point at infinity
   - Compressed form, invalid, `x^3 + ax + b` results in quadratic non-residue in modular square root computation.


## Miscellaneous
Some miscellaneous tests, tries ECDH and ECDSA over super-singular curves, anomalous curves and Barreto-Naehrig curves with small embedding degree and CM discriminant.
Also tests ECDH over MNT curves, M curves and Curve25519 transformed into short Weierstrass form.


## Signature
Tests ECDSA verification, with well-formed but invalid and malformed signatures.

- Well-formed(DER) invalid signatures:
    - r = random, s = random
    - r = 0, s = random
    - r = random, s = 0
    - r = 1, s = random
    - r = random, s = 1
    - r = 0, s = 0
    - r = 0, s = 1
    - r = 1, s = 0
    - r = 1, s = 1
    - r = random, s = p
    - r = random, s = 2 * p
- Invalid signatures:
    - Signature shorter than specified in ASN.1 SEQUENCE header.
    - Signature longer than specified in ASN.1 SEQUENCE header.
    - r shorter/longer than specified in its ASN.1 header.
    - s shorter/longer than specified in its ASN.1 header.
    - ASN.1 SEQUENCE has indefinite length.
    - ASN.1 SEQUENCE has length that will overflow a 16 bit integer.
    - ASN.1 SEQUENCE has length that will overflow a 32 bit integer.
    - ASN.1 SEQUENCE has length that will overflow a 64 bit integer.
- Test verifying a valid signature, but with a negated public key.


## Wrong
Tests on a category of wrong curves. These curves are not really curves as they have:

 - non-prime field in the prime-field case
 - reducible polynomial as the field polynomial in the binary case

This test suite also does some additional tests with corrupting the parameters:

 - Fp:
    - p = 0
    - p = 1
    - p = q^2; q prime
    - p = q * s; q and s prime
    - G = random point not on curve
    - G = random data
    - G = infinity
    - r = 0
    - r = 1
    - r = some prime larger than original r (and [r]G != infinity)
    - r = some prime smaller than original r (and [r]G != infninity)
    - r = some composite number (and [r]G != infinity)
    - k = 0xff
    - k = 0

 - F2m:
    - e1 = e2 = e3 = 0
    - m < e1 < e2 < e3


## Composite
Tests using curves that don't have a prime order/nearly prime order.
These tests should generally fail, a success here implies the target will use a non-secure curve if such curve is set
by the applet. Operations over such curves are susceptible to small-subgroup attacks.

   - r = quite a smooth number, many small factors, r = \|G\|
   - r = prime(of increasing bit lengths), r = \|G\|

     This is performed over a 160 bit field size, in two passes:
      - First pass tests the full range from 2 bits to 152, with more frequent tests towards the beginning and end.
      - The second pass tests the range 140 - 158 bits with one bit steps.

   - r = p * q = \|G\|
   - r = G = Carmichael number = p * q * s
   - [r]G = infinity but r != \|G\|, so \|G\| divides r


## Invalid
Tests using known named curves from several categories(SECG/NIST/Brainpool) against pre-generated *invalid* public keys.
ECDH should definitely fail, a success here implies the target is susceptible to invalid curve attacks.

See [Practical Invalid Curve Attacks on TLS-ECDH](https://www.nds.rub.de/media/nds/veroeffentlichungen/2015/09/14/main-full.pdf) for more information.


## Twist
Tests using known named curves froms several categories(SECG/NIST) against pre-generated points on twists of said curves.
ECDH should fail, a success here implies the target is not twist secure, if a curve with an unsecure twist is used,
the target might compute on the twist, if a point on the twist is supplied.

See [SafeCurves on twist security](https://safecurves.cr.yp.to/twist.html) for more information.


## Degenerate
Tests using known named curves froms several categories(SECG/NIST) against pre-generated points on the degenerate line
`Y: x = 0`. ECDH should fail, a success here might mean the target does not check that the point lies on the correct curve
and uses a curve model vulnerable to such degenerate points.

See [Degenerate Curve Attacks - Extending Invalid Curve Attacks to Edwards Curves and Other Models](https://eprint.iacr.org/2015/1233.pdf) for more information.


## Cofactor
Tests whether the target correctly rejects points that lie on the curve but not on the subgroup generated by the specified generator
during ECDH. Does this with curves where the cofactor subgroup has small order, then with curves that have order equal to the product
of two large primes, sets the generator with order of one prime and tries points on the subgroup of the other prime order.


## Edge-Cases
Tests various inputs to ECDH which may cause an implementation to achieve a certain edge-case state during ECDH.
Some of the data is from the google/Wycheproof project. Tests include [CVE-2017-10176](https://nvd.nist.gov/vuln/detail/CVE-2017-10176) and [CVE-2017-8932](https://nvd.nist.gov/vuln/detail/CVE-2017-8932) and an OpenSSL modular reduction bug
presented in [Practical realisation and elimination of an ECC-related software bug attack](https://eprint.iacr.org/2011/633).
Various custom edge private key values are also tested.

CVE-2017-10176 was in implementation issue in the SunEC Java library (and NSS ([CVE-2017-7781](https://nvd.nist.gov/vuln/detail/CVE-2017-7781)), thus also anything that used it) that caused the implementation to reach the point at infinity during ECDH computation.
See [blog](http://blog.intothesymmetry.com/2017/08/cve-2017-7781cve-2017-10176-issue-with.html) for more info.

CVE-2017-8932 was an implementation issue in the Go standard library, in particular its scalar multiplication algorithm on the
P-256 curve which leaked information about the private key.

Custom edge-case private key values over SECG curves are tested:

   - s = 0, s = 1
   - s < r, s = r, s > r
   - s = r - 1, s = r + 1
   - s = k\*r - 1, s = k\*r, s = k\*r + 1
   - s = 111111...1111, s = 101010...1010, s = 010101...0101
   - s around r (s < r, on a curve where \|r\| > \|p\|)
   - s around p (on a curve where where \|r\| > \|p\|)
   - s around 0 (s > 0, on a curve where \|r\| > \|p\|)
