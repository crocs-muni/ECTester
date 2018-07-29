#include "c_utils.h"
#define _ISOC99_SOURCE
#include <string.h>

jclass ec_parameter_spec_class;
jclass ecgen_parameter_spec_class;
jclass pubkey_class;
jclass privkey_class;
jclass keypair_class;
jclass elliptic_curve_class;
jclass fp_field_class;
jclass f2m_field_class;
jclass point_class;
jclass biginteger_class;
jclass illegal_state_exception_class;

void init_classes(JNIEnv *env, const char* lib_name) {
    jclass local_ec_parameter_spec_class = (*env)->FindClass(env, "java/security/spec/ECParameterSpec");
    ec_parameter_spec_class = (*env)->NewGlobalRef(env, local_ec_parameter_spec_class);

    jclass local_ecgen_parameter_spec_class = (*env)->FindClass(env, "java/security/spec/ECGenParameterSpec");
    ecgen_parameter_spec_class = (*env)->NewGlobalRef(env, local_ecgen_parameter_spec_class);

    const char *pubkey_base = "cz/crcs/ectester/standalone/libs/jni/NativeECPublicKey$";
	char pubkey_class_name[2048] = { 0 }; //strlen(pubkey_base) + strlen(lib_name) + 1
    pubkey_class_name[0] = 0;
    strcat(pubkey_class_name, pubkey_base);
    strcat(pubkey_class_name, lib_name);

    jclass local_pubkey_class = (*env)->FindClass(env, pubkey_class_name);
    pubkey_class = (*env)->NewGlobalRef(env, local_pubkey_class);

    const char *privkey_base = "cz/crcs/ectester/standalone/libs/jni/NativeECPrivateKey$";
	char privkey_class_name[2048] = { 0 }; //strlen(privkey_base) + strlen(lib_name) + 1
    privkey_class_name[0] = 0;
    strcat(privkey_class_name, privkey_base);
    strcat(privkey_class_name, lib_name);

    jclass local_privkey_class = (*env)->FindClass(env, privkey_class_name);
    privkey_class = (*env)->NewGlobalRef(env, local_privkey_class);

    jclass local_keypair_class = (*env)->FindClass(env, "java/security/KeyPair");
    keypair_class = (*env)->NewGlobalRef(env, local_keypair_class);

    jclass local_elliptic_curve_class = (*env)->FindClass(env, "java/security/spec/EllipticCurve");
    elliptic_curve_class = (*env)->NewGlobalRef(env, local_elliptic_curve_class);

    jclass local_fp_field_class = (*env)->FindClass(env, "java/security/spec/ECFieldFp");
    fp_field_class = (*env)->NewGlobalRef(env, local_fp_field_class);

    jclass local_f2m_field_class = (*env)->FindClass(env, "java/security/spec/ECFieldF2m");
    f2m_field_class = (*env)->NewGlobalRef(env, local_f2m_field_class);

    jclass local_biginteger_class = (*env)->FindClass(env, "java/math/BigInteger");
    biginteger_class = (*env)->NewGlobalRef(env, local_biginteger_class);

    jclass local_point_class = (*env)->FindClass(env, "java/security/spec/ECPoint");
    point_class = (*env)->NewGlobalRef(env, local_point_class);

    jclass local_illegal_state_exception_class = (*env)->FindClass(env, "java/lang/IllegalStateException");
    illegal_state_exception_class = (*env)->NewGlobalRef(env, local_illegal_state_exception_class);
}

void throw_new(JNIEnv *env, const char *class, const char *message) {
    jclass clazz = (*env)->FindClass(env, class);
    (*env)->ThrowNew(env, clazz, message);
}

void throw_new_var(JNIEnv *env, const char *class, const char *format, ...) {
	char buffer[2048];
	va_list args;
	va_start(args, format);
	int res = vsnprintf(buffer, 2048, format, args);
	va_end(args);
	throw_new(env, class, buffer);
}