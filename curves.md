---
---
# Curves
ECTester contains a collection of elliptic curve/point parameters, these parameters either come from standards or
were generated manually or using [ecgen](https://github.com/J08nY/ecgen).


## Standard

### SECG
SEC 2: Recommended Elliptic Curve Domain Parameters version 2.0  January 27, 2010

[Source](http://www.secg.org/sec2-v2.pdf)

### NIST
RECOMMENDED ELLIPTIC CURVES FOR FEDERAL GOVERNMENT USE  July 1999

[Source](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)

### x962
ANSI X9.62 example curves.

### Brainpool
ECC Brainpool Standard Curves and Curve Generation v. 1.0  19.10.2005

[Source](http://www.ecc-brainpool.org/download/Domain-parameters.pdf)

### anssi
Agence nationale de la sécurité des systèmes d'information: Publication d'un paramétrage de courbe elliptique visant des applications de passeport électronique et de l'administration électronique française. 21 November 2011

### GOST
GOST R 34.10-2001: RFC5832 curves.

[Source](https://tools.ietf.org/html/rfc5832)


## Generated

### anomalous
These prime field curves have the same order as the field order, and are susceptible to attacks reducing ECDLP over a multiplicative group of the curve, to DLP over an additive group of the underlying field, which is easy (linear time).

Some of these are from Atsuko Miyaji's [paper](https://dspace.jaist.ac.jp/dspace/bitstream/10119/4464/1/73-61.pdf), others were generated using [ecgen](htps://github.com/J08nY/ecgen).

### invalid
This category contains pre-generated invalid curves for a large subset of NIST, SECG and Brainpool curves. Invalid curves for a given curve, are short Weierstrass curves with all parameters equal to the given curve except the `b` parameter. These curves can be used to [attack some implementations](https://www.nds.rub.de/media/nds/veroeffentlichungen/2015/09/14/main-full.pdf).

Generated using [ecgen](https://github.com/J08nY/ecgen).

### composite
Contains curves of composite order, with small order points.

Generated using [ecgen](https://github.com/J08nY/ecgen).

### wrong
Contains parameters that are not elliptic curves(over Fp and F2m), such as `p` parameter that is not prime or an irreducible polynomial that is not irreducible.

Generated manually.

### twist
Contains pre-generated points on twists of known named curves from NIST, SECG.
These points can be used to attack some implementations.

Generated using [ecgen](https://github.com/J08nY/ecgen).