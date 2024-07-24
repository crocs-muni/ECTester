###############################################################################
## General CC setup.

CC?=gcc
CXX?=g++

LFLAGS+=-fPIC -shared -L "$(JNI_LIBDIR)" -L "$(JNI_LIBDIR)/server" #-ljsig -ljvm
CFLAGS+=-fPIC -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I. -Wno-deprecated-declarations
CXXFLAGS+=-fPIC -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I. -Wno-deprecated-declarations

DEBUG ?= 0
PROJECT_ROOT_PATH ?= ../../../../../../../../../..

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
  JNI_LIBDIR ?= $(JAVA_HOME)/lib
endif

ifeq ($(JNI_INCLUDEDIR),)
  $(error "Could not determine JNI include dir. Try specifying either JAVA_HOME or JNI_INCLUDEDIR.")
endif

ifeq ($(JNI_LIBDIR),)
  $(error "Could not determine JNI lib dir. Try specifying either JAVA_HOME or JNI_LIBDIR.")
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

all: tomcrypt botan cryptopp openssl boringssl gcrypt mbedtls ippcp nettle libressl

# Common utils
c_utils.o: c_utils.c
	$(CC) $(CFLAGS) -c $<

lib_timing.so: c_timing.c
	$(CC) -o $@ -shared $(CFLAGS) -Wl,-soname,lib_timing.so $<

lib_csignals.so: c_signals.c
	$(CC) -o $@ -shared $(CFLAGS) -pthread -lpthread -Wl,-soname,lib_csignals.so $<

lib_cppsignals.so: cpp_signals.cpp
	$(CC) -o $@ -shared $(CFLAGS) -pthread -lpthread -Wl,-soname,lib_cppsignals.so $<

cpp_utils.o: cpp_utils.cpp
	$(CXX) $(CXXFLAGS) -c $<


# OpenSSL shim
openssl: openssl_provider.so

openssl_provider.so: openssl.o c_utils.o | lib_timing.so lib_csignals.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs openssl) -l:lib_timing.so -l:lib_csignals.so

openssl.o: openssl.c
	$(CC) $(shell pkg-config --cflags openssl) $(CFLAGS) -c $<


# BoringSSL shim
boringssl: boringssl_provider.so

boringssl_provider.so: boringssl.o c_utils.o | lib_timing.so lib_csignals.so
	NIX_CFLAGS_COMPILE= $(CC) $(CFLAGS) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. -Wl,-Bstatic -l:lib_boringssl.a -Wl,-Bdynamic -l:lib_timing.so -l:lib_csignals.so

boringssl.o: boringssl.c
	NIX_CFLAGS_COMPILE= $(CC) -I$(BORINGSSL_CFLAGS) $(CFLAGS) -c $<


# libgcrypt shim
gcrypt: gcrypt_provider.so

gcrypt_provider.so: gcrypt.o c_utils.o | lib_timing.so lib_csignals.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. -pthread -lpthread -Wl,-Bstatic $(shell libgcrypt-config --libs) -Wl,-Bdynamic -l:lib_timing.so -l:lib_csignals.so

gcrypt.o: gcrypt.c
	$(CC) $(shell libgcrypt-config --cflags) $(CFLAGS) -c $<


# Libtomcrypt shim
tomcrypt: tomcrypt_provider.so

tomcrypt_provider.so: tomcrypt.o c_utils.o | lib_timing.so lib_csignals.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. -ltommath $(shell pkg-config --libs libtomcrypt) -l:lib_timing.so -l:lib_csignals.so

tomcrypt.o: tomcrypt.c
	$(CC) -DLTM_DESC $(shell pkg-config --cflags libtomcrypt) $(CFLAGS) -c $<


# Botan-2 shim
botan: botan_provider.so

botan_provider.so: botan.o cpp_utils.o | lib_timing.so lib_cppsignals.so
	$(CXX) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs botan-2) -l:lib_timing.so -l:lib_cppsignals.so

botan.o: botan.cpp
	$(CXX) $(shell pkg-config --cflags botan-2) $(CXXFLAGS) -c $<


# Crypto++ shim
CRYPTOPP_NAME := "libcrypto++"
ifeq ($(shell pkg-config --exists $(CRYPTOPP_NAME); echo $$?),1)
	CRYPTOPP_NAME := "libcryptopp"
endif
cryptopp: cryptopp_provider.so

cryptopp_provider.so: cryptopp.o cpp_utils.o | lib_timing.so lib_cppsignals.so
	$(CXX) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs $(CRYPTOPP_NAME)) -l:lib_timing.so -l:lib_cppsignals.so

cryptopp.o: cryptopp.cpp
	$(CXX) $(shell pkg-config --cflags $(CRYPTOPP_NAME)) $(CXXFLAGS) -c $<


# mbedTLS shim
mbedtls: mbedtls_provider.so

mbedtls_provider.so: mbedtls.o c_utils.o | lib_timing.so lib_csignals.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. -lmbedcrypto -l:lib_timing.so -l:lib_csignals.so

mbedtls.o: mbedtls.c
	$(CC) $(CFLAGS) -c $<



# Intel Performance Primitives crypto shim
ippcp: ippcp_provider.so

ippcp_provider.so: ippcp.o c_utils.o | lib_timing.so lib_csignals.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L$(IPP_CRYPTO_LIB) -Wl,-Bstatic -l:libippcp.a -L. -Wl,-Bdynamic -l:lib_timing.so -l:lib_csignals.so

ippcp.o: ippcp.c
	$(CC) -I$(IPP_CRYPTO_HEADER) $(CFLAGS) -c $<


# Nettle shim
nettle: nettle_provider.so

nettle_provider.so: nettle.o c_utils.o | lib_timing.so lib_csignals.so
	$(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs nettle) -l:lib_timing.so -l:lib_csignals.so $(shell pkg-config --libs hogweed) -lgmp

nettle.o: nettle.c
	$(CC) $(shell pkg-config --cflags nettle) $(shell pkg-config --libs hogweed) -lgmp $(CFLAGS) -c $<


# LibreSSL shim
libressl: libressl_provider.so

libressl_provider.so: libressl.o c_utils.o | lib_timing.so lib_csignals.so
	NIX_CFLAGS_COMPILE= $(CC) $(LFLAGS) -o $@ -Wl,-rpath,'$$ORIGIN/lib' $^ -L. $(shell pkg-config --libs libresslcrypto) -l:lib_timing.so -l:lib_csignals.so

libressl.o: libressl.c
	NIX_CFLAGS_COMPILE= $(CC) $(shell pkg-config --cflags libresslcrypto) $(CFLAGS) -c $<

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
	@echo "    - nettle"
	@echo "    - libressl"


clean:
	rm -rf *.o
	rm -rf *.so

.PHONY: all help clean openssl boringssl gcrypt tomcrypt botan cryptopp mbedtls ippcp nettle libressl
