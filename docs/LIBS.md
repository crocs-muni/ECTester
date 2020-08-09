# Supported libraries

Libraries that ECTester can test.

 - [BouncyCastle](https://bouncycastle.org/java.html)
    - Java
    - Works with the short Weierstrass curve model for ECDSA and ECDH.
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
 - [WolfCrypt(WolfSSL)](https://www.wolfssl.com)
    - C + Java
    - Prime field curves only.
    - Jacobian coordinates:
        - Uses sliding window scalar multiplication, (discards `b` parameter of curve), but validates points.
 - [OpenSSL](https://www.openssl.org/)
    - C
    - For prime field curves:
        - Uses Jacobian coordinates, and Montgomery ladder, also uses wNAF-based interleaving multi-exponentiation method(ec_mult.c): http://www.bmoeller.de/pdf/TI-01-08.multiexp.pdf
        - Also uses multiplication with precomputation by wNAF splitting(ec_mult.c)
    - For binary field curves:
        - Uses Jacobian coordinates, and Lopez-Dahab ladder, also uses wNAF-based interleaving multi-exponentiation method(ec2_smpl.c)
 - [BoringSSL](https://boringssl.googlesource.com/boringssl)
    - C
    - Supports prime field curves only:
       - Use Jacobian coordinates, and Montgomery ladder, also uses optimized arithmetic on NIST P-224, P-256.
    - Bundled as a git submodule in `ext/boringssl`. To build and use run:
```bash
cd ext/boringssl
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=1 -GNinja ..
ninja
```
 - [Crypto++](https://cryptopp.com/)
    - C++
    - For prime field curves:
        - Uses projective coordinates and sliding window scalar multiplication algorithm.
    - For binary field curves:
        - Uses affine coordinates and sliding window scalar multiplication algorithm.
 - [libtomcrypt](http://www.libtom.net/LibTomCrypt/)
    - C
    - Uses Jacobian coordinates.
    - Sliding window scalar multiplication algorithm.
 - [libgcrypt](https://www.gnupg.org/related_software/libgcrypt/)
    - C
    - Only supports prime field curves.
    - Uses short Weierstrass, Montgomery and Twisted Edwards models.
       - Uses left-to-right double-and-add always scalar multiplication and Jacobian coordinates in short Weierstrass form.
       - Uses Montgomery ladder and X-only in Montgomery form.
       - Uses left-to-right double-and-add always scalar multiplication in Twisted Edwards form.
 - [Botan](https://botan.randombit.net/)
    - C++
    - Uses blinded(randomized) Montgomery ladder.
    - <https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2>
    - <https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc>
    - <https://eprint.iacr.org/2015/657>
    - ECTester supports v2.4.0 and up.
 - [Microsoft CNG](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx)
    - C API.
    - <del>Closed source.</del> Not any more: <https://github.com/Microsoft/SymCrypt>.
	- For prime field curves(only supports):
	   - Uses Short Weierstrass model.
	   - Uses Twisted Edwards model.
	   - Uses Montgomery model.
	   - Uses fixed window scalar multiplication.
	   - Uses Wnaf multi-scalar multiplication with interleaving.
	   - Uses Montgomery ladder.
 - [mbedTLS](https://tls.mbed.org/)
    - C
    - Only supports prime field curves.
    - Uses short Weierstrass and Montgomery models.
    - Uses comb method for short Weierstrass curves, using (randomized) Jacobian coordinates.
    - <http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2>
    - Uses Montgomery ladder with xz coordinates for Montgomery curves.
 - [MatrixSSL](https://github.com/matrixssl/matrixssl)
    - C
    - Only supports prime field curves.
    - Uses 4 bit sliding window.
    - Uses projective coordinates.
 - [Intel Performance Primitives](https://software.intel.com/en-us/ipp-crypto-reference-2019)
    - C
    - Only supports prime field curves.
    - Uses 5-bit window NAF.
    - Uses Jacobian coordinates.
    - <https://github.com/intel/ipp-crypto>
 - [Nettle](http://www.lysator.liu.se/~nisse/nettle/)
    - C
    - No support for explicit parameters, only SECG named curves.
    - Uses Jacobian coordinates.
    - <https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b>
    - <https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl>
    - <https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl>
    - Uses double-and-add always or windowing algorithm.
    - Uses Pippenger scalar mult for Twisted Edwards curves.
 - [LibreSSL](https://www.libressl.org/)
    - C

# Libraries with ECC support

Popular libraries with at least some ECC support, that ECTester does not yet support:

 - [NSS](https://hg.mozilla.org/projects/nss)
 - [BearSSL](https://bearssl.org/)*
 - [cryptlib](https://www.cryptlib.com/)*
 - [OpenSSL (FIPS mode)](https://www.openssl.org/docs/fipsnotes.html)
 - [Microsoft .NET crypto](https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
 - [Linux kernel](https://kernel.org), test via [libkcapi](http://chronox.de/libkcapi.html)

* Signifies libraries for which adding support would be very much appreciated.