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

all: tomcrypt_provider.so botan_provider.so cryptopp_provider.so openssl_provider.so boringssl_provider.so gcrypt_provider.so mbedtls_provider.so

# Common utils
c_utils.o: c_utils.c
	$(CC) $(CFLAGS) -c $<

c_timing.o: c_timing.c
	$(CC) $(CFLAGS) -c $<

cpp_utils.o: cpp_utils.cpp
	$(CXX) $(CXXFLAGS) -c $<


# OpenSSL shim
openssl_provider.so: openssl.o c_utils.o c_timing.o
	$(CC) $(LFLAGS) -o $@ $^ -L. $(shell pkg-config --libs openssl)

openssl.o: openssl.c
	$(CC) $(shell pkg-config --cflags openssl) $(CFLAGS) -c $<


# BoringSSL shim
boringssl_provider.so: boringssl.o c_utils.o c_timing.o
	$(CC) $(LFLAGS) -o $@ $^ -L. ../../../../../../../ext/boringssl/build/crypto/libcrypto.so
	cp ../../../../../../../ext/boringssl/build/crypto/libcrypto.so lib_boringssl.so

boringssl.o: boringssl.c
	$(CC) -I../../../../../../../ext/boringssl/include/ $(CFLAGS) -c $<


# libgcrypt shim
gcrypt_provider.so: gcrypt.o c_utils.o c_timing.o
	$(CC) $(LFLAGS) -o $@ $^ -L. $(shell libgcrypt-config --libs)

gcrypt.o: gcrypt.c
	$(CC) $(shell libgcrypt-config --cflags) $(CFLAGS) -c $<


# Libtomcrypt shim
tomcrypt_provider.so: tomcrypt.o c_utils.o c_timing.o
	$(CC) $(LFLAGS) -o $@ $^ -L. -ltommath $(shell pkg-config --libs libtomcrypt)

tomcrypt.o: tomcrypt.c
	$(CC) -DLTM_DESC $(shell pkg-config --cflags libtomcrypt) $(CFLAGS) -c $<


# Botan-2 shim
botan_provider.so: botan.o cpp_utils.o c_timing.o
	$(CXX) $(LFLAGS) -o $@ $^ -L. $(shell pkg-config --libs botan-2)

botan.o: botan.cpp
	$(CXX) $(shell pkg-config --cflags botan-2) $(CXXFLAGS) -c $<


# Crypto++ shim
cryptopp_provider.so: cryptopp.o cpp_utils.o c_timing.o
	$(CXX) $(LFLAGS) -o $@ $^ -L. $(shell pkg-config --libs libcrypto++)

cryptopp.o: cryptopp.cpp
	$(CXX) $(shell pkg-config --cflags libcrypto++) $(CXXFLAGS) -c $<


# mbedTLS shim
mbedtls_provider.so: mbedtls.o c_utils.o c_timing.o
	$(CC) $(LFLAGS) -o $@ $^ -L. -lmbedcrypto

mbedtls.o: mbedtls.c
	$(CC) $(CFLAGS) -c $<

help:
	@echo "# This makefile builds the JNI shims necessary to test native libraries."
	@echo "# Targets:"
	@echo "    - openssl_provider.so"
	@echo "    - boringssl_provider.so"
	@echo "    - gcrypt_provider.so"
	@echo "    - tomcrypt_provider.so"
	@echo "    - botan_provider.so"
	@echo "    - cryptopp_provider.so"
	@echo "    - mbedtls_provider.so"

clean:
	rm -rf *.o
	rm -rf *.so

.PHONY: all help clean