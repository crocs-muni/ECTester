#pragma once

#include "native.h"
#include <stdbool.h>

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
void init_classes(JNIEnv *env, const char* lib_name);

/**
 * Throw a new exception of class with message.
 */
void throw_new(JNIEnv *env, const char *class, const char *message);

/**
 * Throw a new exception of class, with formatted message.
 */
void throw_new_var(JNIEnv *env, const char *class, const char *format, ...);

/**
 * Get the size of the specified key algorithm in bits, for ECDH KDF output size.
 */
jint get_kdf_bits(JNIEnv *env, jstring algorithm);

/**
 * DER encode the r and s values.
 */
jbyteArray asn1_der_encode(JNIEnv *env, const jbyte *r, size_t r_len, const jbyte *s, size_t s_len);

/**
 * DER decode a signature into r and s values.
 */
bool asn1_der_decode(JNIEnv *env, jbyteArray sig, jbyte **r_data, size_t *r_len, jbyte **s_data, size_t *s_len);

/**
 * Convert a BigInteger to an allocated hex string.
 */
char *biginteger_to_hex(JNIEnv *env, jobject big, jint bytes);

/**
 * Some useful defines to init the provider.
 */
#define INIT_PROVIDER(env, provider_class) jmethodID provider_put = (*env)->GetMethodID(env, provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")
#define ADD_PROPERTY(env, self, base_name, base_class, prop_name, prop_class) do {                                                              \
                                                                           jstring ec = (*env)->NewStringUTF(env, base_name prop_name);         \
                                                                           jstring ec_value = (*env)->NewStringUTF(env, base_class prop_class); \
                                                                           (*env)->CallObjectMethod(env, self, provider_put, ec, ec_value);     \
                                                                       } while (0)
#define ADD_KPG(env, self, kpg_name, kpg_class)       ADD_PROPERTY(env, self, "KeyPairGenerator.", "cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$", kpg_name, kpg_class)
#define ADD_KA(env, self, ka_name, ka_class)          ADD_PROPERTY(env, self, "KeyAgreement.", "cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$", ka_name, ka_class)
#define ADD_SIG(env, self, sig_name, sig_class)       ADD_PROPERTY(env, self, "Signature.", "cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$", sig_name, sig_class)