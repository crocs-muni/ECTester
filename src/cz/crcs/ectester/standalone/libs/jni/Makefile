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
    # add more checks here
    endif
  endif
endif

JNI_PLATFORMINCLUDEDIR ?= $(JNI_INCLUDEDIR)/$(JNI_PLATFORM)

LOCAL_INCLUDES = /usr/local/include
LOCAL_LIBS = /usr/local/lib

CC?=gcc
CXX?=g++
STRIP?=strip

CFLAGS+=-fPIC -g -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I.
CXXFLAGS+=-fPIC -g -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I.


all: tomcrypt_provider.so botan_provider.so cryptopp_provider.so

# Common utils
c_utils.o: c_utils.c
	$(CC) $(CFLAGS) -c $<

cpp_utils.o: cpp_utils.cpp
	$(CXX) $(CXXFLAGS) -c $<


# Libtomcrypt shim
tomcrypt_provider.so: tomcrypt.o c_utils.o
	$(CC) -fPIC -g -shared -o $@ $^ -L. -ltommath $(shell pkg-config --libs libtomcrypt)

tomcrypt.o: tomcrypt.c
	$(CC) -DLTM_DESC $(shell pkg-config --cflags libtomcrypt) $(CFLAGS) -c $<


# Botan-2 shim
botan_provider.so: botan.o cpp_utils.o
	$(CXX) -fPIC -g -shared -o $@ $^ -L. $(shell pkg-config --libs botan-2)

botan.o: botan.cpp
	$(CXX) $(shell pkg-config --cflags botan-2) $(CXXFLAGS) -c $<


# Crypto++ shim
cryptopp_provider.so: cryptopp.o cpp_utils.o
	$(CXX) -fPIC -g -shared -o $@ $^ -L. $(shell pkg-config --libs libcrypto++)

cryptopp.o: cryptopp.cpp
	$(CXX) $(shell pkg-config --cflags libcrypto++) $(CXXFLAGS) -c $<


clean:
	rm -rf *.o
	rm -rf *.so

.PHONY: all clean