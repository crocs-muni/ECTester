###############################################################################
## General CC setup.

CC?=gcc
CXX?=g++

LFLAGS+=-fPIC -shared
CFLAGS+=-fPIC -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I.
CXXFLAGS+=-fPIC -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I.

DEBUG ?= 0

ifeq ($(DEBUG), 1)
  CFLAGS+=-g -Wall
  LFLAGS+=-g
  CXXFLAGS+=-g -Wall
else
  CFLAGS+=-O2
  LFLAGS+=-O2
  CXXFLAGS+=-O2
endif

###############################################################################
## Java JNI setup.

ifeq ($(JAVA_HOME),)
  ifeq ($(OS),Windows_NT)
    which = $(shell where $1)
  else
    which = $(shell which $1)
  endif
  JAVAC ?= $(realpath $(call which,javac))
  JAVA_HOME = $(abspath $(dir $(JAVAC))..)
endif

ifneq ($(JAVA_HOME),)
  JNI_INCLUDEDIR ?= $(JAVA_HOME)/include
endif

ifeq ($(JNI_INCLUDEDIR),)
  $(error Could not determine JNI include dir. Try specifying either JAVA_HOME or JNI_INCLUDEDIR.)
endif

TARGETTRIPLET := $(shell $(CC) -dumpmachine)

ifeq ($(JNI_PLATFORM),)
  ifeq ($(findstring mingw,$(TARGETTRIPLET)),mingw)
  JNI_PLATFORM:= win32
  else
    ifeq ($(findstring linux,$(TARGETTRIPLET)),linux)
      JNI_PLATFORM:= linux
    endif
  endif
endif

JNI_PLATFORMINCLUDEDIR ?= $(JNI_INCLUDEDIR)/$(JNI_PLATFORM)

###############################################################################
## Targets.

all: tomcrypt botan cryptopp openssl boringssl gcrypt mbedtls ippcp matrixssl nettle libressl

# Common utils
c_utils.o: c_utils.c
	$(CC) $(CFLAGS) -c $<

lib_timing.so: c_timing.c
	$(CC) -o $@ -shared $(CFLAGS) -Wl,-soname,lib_timing.so $<

cpp_utils.o: cpp_utils.cpp
	$(CXX) $(CXXFLAGS) -c $<


# OpenSSL shim
openssl: openssl_provider.so

openssl_provider.so: openssl.o c_utils.o | lib_timing.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs openssl) -l:lib_timing.so

openssl.o: openssl.c
	$(CC) $(shell pkg-config --cflags openssl) $(CFLAGS) -c $<


# BoringSSL shim
boringssl: boringssl_provider.so

lib_boringssl.so:
	cp ../../../../../../../ext/boringssl/build/crypto/libcrypto.so lib_boringssl.so

boringssl_provider.so: boringssl.o c_utils.o | lib_timing.so lib_boringssl.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. lib_boringssl.so -l:lib_timing.so

boringssl.o: boringssl.c
	$(CC) -I../../../../../../../ext/boringssl/include/ $(CFLAGS) -c $<


# libgcrypt shim
gcrypt: gcrypt_provider.so

gcrypt_provider.so: gcrypt.o c_utils.o | lib_timing.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell libgcrypt-config --libs) -l:lib_timing.so

gcrypt.o: gcrypt.c
	$(CC) $(shell libgcrypt-config --cflags) $(CFLAGS) -c $<


# Libtomcrypt shim
tomcrypt: tomcrypt_provider.so

tomcrypt_provider.so: tomcrypt.o c_utils.o | lib_timing.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. -ltommath $(shell pkg-config --libs libtomcrypt) -l:lib_timing.so

tomcrypt.o: tomcrypt.c
	$(CC) -DLTM_DESC $(shell pkg-config --cflags libtomcrypt) $(CFLAGS) -c $<


# Botan-2 shim
botan: botan_provider.so

botan_provider.so: botan.o cpp_utils.o | lib_timing.so
	$(CXX) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs botan-2) -l:lib_timing.so

botan.o: botan.cpp
	$(CXX) $(shell pkg-config --cflags botan-2) $(CXXFLAGS) -c $<


# Crypto++ shim
CRYPTOPP_NAME := "libcrypto++"
ifeq ($(shell pkg-config --exists $(CRYPTOPP_NAME); echo $$?),1)
	CRYPTOPP_NAME := "libcryptopp"
endif
cryptopp: cryptopp_provider.so

cryptopp_provider.so: cryptopp.o cpp_utils.o | lib_timing.so
	$(CXX) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs $(CRYPTOPP_NAME)) -l:lib_timing.so

cryptopp.o: cryptopp.cpp
	$(CXX) $(shell pkg-config --cflags $(CRYPTOPP_NAME)) $(CXXFLAGS) -c $<


# mbedTLS shim
mbedtls: mbedtls_provider.so

mbedtls_provider.so: mbedtls.o c_utils.o | lib_timing.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. -lmbedcrypto -l:lib_timing.so

mbedtls.o: mbedtls.c
	$(CC) $(CFLAGS) -c $<


# Intel Performance Primitives crypto shim
ippcp: ippcp_provider.so

ippcp_provider.so: ippcp.o c_utils.o
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. -lippcp -l:lib_timing.so

ippcp.o: ippcp.c
	$(CC) $(CFLAGS) -c $<


# MatrixSSL shim
matrixssl: matrixssl_provider.so

matrixssl_provider.so: matrixssl.o c_utils.o | lib_timing.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' -L. $^ libcrypt_s.a libcore_s.a -l:lib_timing.so

matrixssl.o: matrixssl.c
	$(CC) $(CFLAGS) -Imatrixssl/ -c $<


# Nettle shim
nettle: nettle_provider.so

nettle_provider.so: nettle.o c_utils.o | lib_timing.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs nettle) -l:lib_timing.so $(shell pkg-config --libs hogweed) -lgmp

nettle.o: nettle.c
	$(CC) $(shell pkg-config --cflags nettle) $(shell pkg-config --libs hogweed) -lgmp $(CFLAGS) -c $<


# LibreSSL shim
libressl: libressl_provider.so

lib_libressl.so:
	cp ../../../../../../../ext/libressl/build/crypto/libcrypto.so lib_libressl.so

libressl_provider.so: libressl.o c_utils.o | lib_timing.so lib_libressl.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. lib_libressl.so -l:lib_timing.so

libressl.o: libressl.c
	$(CC) -I../../../../../../../ext/libressl/include/ $(CFLAGS) -c $<


help:
	@echo "# This makefile builds the JNI shims necessary to test native libraries."
	@echo "# Targets:"
	@echo "    - openssl"
	@echo "    - boringssl"
	@echo "    - gcrypt"
	@echo "    - tomcrypt"
	@echo "    - botan"
	@echo "    - cryptopp"
	@echo "    - mbedtls"
	@echo "    - ippcp"
	@echo "    - matrixssl"
	@echo "    - nettle"
	@echo "    - libressl"


clean:
	rm -rf *.o
	rm -rf *.so

.PHONY: all help clean openssl boringssl gcrypt tomcrypt botan cryptopp mbedtls ippcp matrixssl nettle libressl
