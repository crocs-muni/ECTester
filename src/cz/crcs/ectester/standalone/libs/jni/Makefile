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
$(error could not determine JNI include dir, try specifying either \
    JAVA_HOME or JNI_INCLUDEDIR)
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


all: tomcrypt_provider.so botan_provider.so

tomcrypt_provider.so: tomcrypt.o
	$(CC) -fPIC -g -shared -o $@ $< -L. -ltommath -ltomcrypt

tomcrypt.o: tomcrypt.c
	$(CC) -DLTM_DESC -fPIC -g -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I. -c $<

botan_provider.so: botan.o
	$(CXX) -fPIC -g -shared -o $@ $< -L. -L"$(LOCAL_LIBS)" -lbotan-2 -fstack-protector -m64 -pthread

botan.o: botan.cpp
	$(CXX) -fPIC -g -I"$(LOCAL_INCLUDES)/botan-2" -I"$(JNI_INCLUDEDIR)" -I"$(JNI_PLATFORMINCLUDEDIR)" -I. -c $<

clean:
	rm -rf *.o
	rm -rf *.so

.PHONY: all clean