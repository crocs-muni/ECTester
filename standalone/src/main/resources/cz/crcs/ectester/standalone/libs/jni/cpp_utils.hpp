#pragma once

#include "native.h"
#include <string>

/**
 * Classes that are accessed alot are cached here, manually.
 */
extern jclass ec_parameter_spec_class;
extern jclass ecgen_parameter_spec_class;
extern jclass secret_key_spec_class;
extern jclass pubkey_class;
extern jclass privkey_class;
extern jclass keypair_class;
extern jclass elliptic_curve_class;
extern jclass fp_field_class;
extern jclass f2m_field_class;
extern jclass point_class;
extern jclass biginteger_class;
extern jclass illegal_state_exception_class;

/**
 * Initialize the classes.
 */
void init_classes(JNIEnv *env, std::string lib_name);

/**
 * Throw a new exception of class with message.
 */
void throw_new(JNIEnv *env, const std::string& klass, const std::string& message);

/**
 * Get the size of the specified key algorithm in bits, for ECDH KDF output size.
 */
jint get_kdf_bits(JNIEnv *env, jstring algorithm);

/**
 * Add a KeyPairGeneratorSpi class to this provider.
 */
void add_kpg(JNIEnv *env, const std::string &type, const std::string &klass, jobject provider, jmethodID put_method);

/**
 * Add a KeyAgreementSpi class to this provider.
 */
void add_ka(JNIEnv *env, const std::string &type, const std::string &klass, jobject provider, jmethodID put_method);

/**
 * Add a SignatureSpi class to this provider.
 */
void add_sig(JNIEnv *env, const std::string &type, const std::string &klass, jobject provider, jmethodID put_method);

/**
 * Version handling.
 */
#define VERSION_GT(lib,a,b,c) ((ECTESTER_##lib##_MAJOR == a && ECTESTER_##lib##_MINOR == b && ECTESTER_##lib##_PATCH > c) || (ECTESTER_##lib##_MAJOR == a && ECTESTER_##lib##_MINOR > b) || (ECTESTER_##lib##_MAJOR > a))
#define VERSION_EQ(lib,a,b,c) (ECTESTER_##lib##_MAJOR == a && ECTESTER_##lib##_MINOR == b && ECTESTER_##lib##_PATCH == c)
#define VERSION_GE(lib,a,b,c) (VERSION_GT(lib,a,b,c) || VERSION_EQ(lib,a,b,c))
#define VERSION_LT(lib,a,b,c) !(VERSION_GE(lib,a,b,c))
#define VERSION_LE(lib,a,b,c) !(VERSION_GT(lib,a,b,c))
