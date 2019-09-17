# Developing ECTester

This document describes some development guidelines and how-tos regarding
developing the ECTester tool itself.

## Developing ECTester standalone modules

 - Create Java classes inheriting Native{ECPrivateKey,ECPublicKey,KeyPairGeneratorSpi,KeyAgreementSpi,SignatureSpi}.
 - Add those classes to `build-standalone.xml` header generation.
 - Generate `native.h` headers for new classes using `build-standalone.xml`.
 - Create module file (C/C++) in `cz/crcs/ectester/standalone/libs/jni`, and add it to the Makefile.
 - Implement the required JNI functions, look at existing modules for what is expected, what the contract
 of the function is, use the `native_timing_*` functions around points that should be measurable.
 - Compile and run ECTester using your new module.