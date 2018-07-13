---
---
# Libraries with ECC support

Popular libraries with at least some ECC support:

 - [libgcrypt](https://www.gnupg.org/related_software/libgcrypt/)
 - [mbedTLS](https://tls.mbed.org/)
 - [Nettle](http://www.lysator.liu.se/~nisse/nettle/)
 - [OpenSSL](https://www.openssl.org/)
 - [OpenSSL (FIPS mode)](https://www.openssl.org/docs/fipsnotes.html)
 - [Microsoft CNG](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx)
 - [Microsoft .NET crypto](https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
 
# Supported libraries

 - [BouncyCastle](https://bouncycastle.org/java.html)
    - Java
    - Works with the short Weierstrass curve model.
    - Works with coordinates:
      - Affine
      - Projective(Homogenous)
      - Jacobian
      - Jacobian-Chudnovsky
      - Jacobian-Modified
      - Lambda-Affine?
      - Lambda-Projective?
      - Skewed?
    - Multiple scalar multiplication algorithms implemented and used:
      - Double-and-add always (DoubleAddMultiplier)
      - Fixed point comb (FixedPointCombMultiplier)
      - GLV (Gallant-Lambert-Vanstone) using endomorphisms (GLVMultiplier): Faster point multiplication on elliptic curves with efficient endomorphisms. <-- default, if available
      - Binary NAF right-to-left multiplication(mixed coordinates) (MixedNafR2LMultiplier)
      - Montgomery ladder (MontgomeryLadderMultiplier)
      - Binary NAF right-to-left multiplication (NafR2LMultiplier)
      - Binary NAF left-to-right multiplication (NafL2RMultiplier)
      - Double-and-add reference implementation (ReferenceMultiplier)
      - Window NAF left-to-right multiplication (WNafL2RMultiplier) <-- default
      - Window Tau-NAF multiplication (WTauNafMultiplier): Improved Algorithms for Arithmetic on Anomalous Binary Curves
      - Zeroless signed digit binary right-to-left multiplication (ZSignedDigitR2LMultiplier)
      - Zeroless signed digit binary left-to-right multiplication (ZSignedDigitL2RMultiplier)
    - Has custom field and point arithmetic for:
      - Curve25519 (transformed into short Weierstrass model)
      - SMP2 curves
      - SECG curves
 - [Sun EC](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunEC)
    - Java + C
    - Uses the short Weierstrass curve model.
    - For prime field curves:
      - Uses 5-bit window NAF, Uses mixed Modified-Jacobian coordinates
        for doubling and Chudnovsky Jacobian coordinates for additions (ecp_jm.c). From:
        Brown, Hankerson, Lopez, Menezes: Software Implementation of the NIST Elliptic Curves Over Prime Fields.
      - Contains an implementation of scalar multiplication with 4-bit sliding window, using Jacobian coordinates (ecp_jac.c)
      - Contains an implementation of IEEE P1363 algorithm A.10.3 using affine coordinates (ecp_aff.c)
    - For binary field curves:
      - Uses Lopez-Dahab (Montgomery) ladder, XZ coordinates (ec2_mont.c): Fast multiplication on elliptic curves over GF(2^m) without precomputation (Algorithm 2P)
      - Contains an implementation of IEEE P1363 algorithm A.10.3 using affine coordinates (ec2_aff.c)
    - Has some custom arithmetic for some of the NIST primes.
 - [Botan](https://botan.randombit.net/)
    - C++
    - Uses blinded(randomized) Montgomery ladder.
    - <https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2>
    - <https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc>
    - <https://eprint.iacr.org/2015/657>
    - ECTester supports v2.4.0 and up.
 - [libtomcrypt](http://www.libtom.net/LibTomCrypt/)
    - C
    - Uses Jacobian coordinates.
    - Sliding window scalar multiplication algorithm.
 - [Crypto++](https://cryptopp.com/)
    - C++