# Supported libraries

Libraries that ECTester can test:

 - [BouncyCastle](https://bouncycastle.org/java.html)
 - [Sun EC](https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunEC)
 - [WolfCrypt(WolfSSL)](https://www.wolfssl.com)
 - [OpenSSL](https://www.openssl.org/)
 - [BoringSSL](https://boringssl.googlesource.com/boringssl)
 - [Crypto++](https://cryptopp.com/)
 - [libtomcrypt](http://www.libtom.net/LibTomCrypt/)
 - [libgcrypt](https://www.gnupg.org/related_software/libgcrypt/)
 - [Botan](https://botan.randombit.net/)
 - [Microsoft CNG](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx)
 - [mbedTLS](https://tls.mbed.org/)
 - [Intel Performance Primitives](https://software.intel.com/en-us/ipp-crypto-reference-2019)
 - [Nettle](http://www.lysator.liu.se/~nisse/nettle/)
 - [LibreSSL](https://www.libressl.org/)

# Libraries with ECC support

Popular libraries with at least some ECC support, that ECTester does not yet support:

 - [NSS](https://hg.mozilla.org/projects/nss)
 - [BearSSL](https://bearssl.org/)*
 - [cryptlib](https://www.cryptlib.com/)*
 - [OpenSSL (FIPS mode)](https://www.openssl.org/docs/fipsnotes.html)
 - [Microsoft .NET crypto](https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
 - [Linux kernel](https://kernel.org), test via [libkcapi](http://chronox.de/libkcapi.html)

* Signifies libraries for which adding support would be very much appreciated.