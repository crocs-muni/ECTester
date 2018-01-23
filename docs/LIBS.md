# Libraries with ECC

Libraries with at least some ECC support:

 - [Crypto++](https://cryptopp.com/)
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
 - [Sun EC](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunEC)
    - Java + C
 - [Botan](https://botan.randombit.net/), since 2.4.0 (unreleased)
    - C++
    - Uses blinded(randomized) Montgomery ladder.
    - https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
    - https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc
    - https://eprint.iacr.org/2015/657
 - [libtomcrypt](http://www.libtom.net/LibTomCrypt/)
    - C
    - Uses Jacobian coordinates.
    - Sliding window scalar multiplication algorithm.