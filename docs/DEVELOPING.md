# Developing ECTester

This document describes some development guidelines and how-tos regarding
developing the ECTester tool itself.

## Developing ECTester standalone modules

 - Create Java classes inheriting Native{ECPrivateKey,ECPublicKey,KeyPairGeneratorSpi,KeyAgreementSpi,SignatureSpi}.
 - Run `gradle :standalone:compileJava` to compile the classes and obtain a native header file. It will be in
 `standalone/build/generated/sources/headers/java/main`. Ideally, copy the generated function declarations into
 the `native.h` file found in the `standalone/src/java/resources/cz/crcs/ectester/standalone/libs/jni` directory.
 - Create module file (C/C++) in `standalone/src/java/resources/cz/crcs/ectester/standalone/libs/jni`, and add it to the Makefile.
 - Implement the required JNI functions, look at existing modules for what is expected, what the contract
 of the function is, use the `native_timing_*` functions around points that should be measurable.
 - Compile and run ECTester using your new module.