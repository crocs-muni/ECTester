#include "c_utils.h"
#define _ISOC99_SOURCE
#include <string.h>
#include <stdlib.h>

#if defined(__WIN32__) || defined(_MSC_VER)
#include <windows.h>
#endif

jclass ec_parameter_spec_class;
jclass ecgen_parameter_spec_class;
jclass secret_key_spec_class;
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

    jclass local_secret_key_spec_class = (*env)->FindClass(env, "javax/crypto/spec/SecretKeySpec");
    secret_key_spec_class = (*env)->NewGlobalRef(env, local_secret_key_spec_class);

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
	vsnprintf(buffer, 2048, format, args);
	va_end(args);
	throw_new(env, class, buffer);
}

jint get_kdf_bits(JNIEnv *env, jstring algorithm) {
    if (algorithm == NULL) {
        return 0;
    }

    const char *algo_data = (*env)->GetStringUTFChars(env, algorithm, NULL);

    jint result = 0;
    if (strcmp(algo_data, "DES") == 0) {
        result = 64;
    } else if (strcmp(algo_data, "BLOWFISH") == 0) {
        result = 128;
    } else if (strcmp(algo_data, "DESEDE") == 0) {
        result = 192;
    } else if (strcmp(algo_data, "AES") == 0 || strcmp(algo_data, "CAMELLIA") == 0) {
        result = 256;
    } else {
        char *end;
        long bits = strtol(algo_data, &end, 10);
        if (*end == 0) {
            result = (jint) bits;
        }
    }
    (*env)->ReleaseStringUTFChars(env, algorithm, algo_data);
    return result;
}

jbyteArray asn1_der_encode(JNIEnv *env, const jbyte *r, size_t r_len, const jbyte *s, size_t s_len) {
    const jbyte *rtmp = r;
    while (*rtmp++ == 0) {
        r++;
        r_len--;
    }
    const jbyte *stmp = s;
    while (*stmp++ == 0) {
        s++;
        s_len--;
    }

    jbyte r_length = (jbyte) r_len + (r[0] & 0x80 ? 1 : 0);
    jbyte s_length = (jbyte) s_len + (s[0] & 0x80 ? 1 : 0);

    // R and S are < 128 bytes, so 1 byte tag + 1 byte len + len bytes value
    size_t seq_value_len = 2 + r_length + 2 + s_length;
    size_t whole_len = seq_value_len;

    // The SEQUENCE length might be >= 128, so more bytes of length
    size_t seq_len_len = 0;
    if (seq_value_len >= 128) {
        size_t s = seq_value_len;
        do {
            seq_len_len++;
        } while ((s = s >> 8));
    }
    // seq_len_len bytes for length and one for length of length
    whole_len += seq_len_len + 1;

    // 1 byte tag for SEQUENCE
    whole_len += 1;

    jbyteArray result = (jbyteArray) (*env)->NewByteArray(env, whole_len);
    jbyte *data = (*env)->GetByteArrayElements(env, result, NULL);
    size_t i = 0;
    data[i++] = 0x30; // SEQUENCE
    if (seq_value_len < 128) {
        data[i++] = (jbyte) seq_value_len;
    } else {
        data[i++] = (jbyte) (seq_len_len | (1 << 7));
        for (size_t j = 0; j < seq_len_len; ++j) {
            data[i++] = (jbyte) (seq_value_len & (0xff << (8 * (seq_len_len - j - 1))));
        }
    }
    data[i++] = 0x02; //INTEGER
    data[i++] = r_length;
    if (r[0] & 0x80) {
        data[i++] = 0;
    }
    memcpy(data + i, r, r_len);
    i += r_len;
    data[i++] = 0x02; //INTEGER
    data[i++] = s_length;
    if (s[0] & 0x80) {
        data[i++] = 0;
    }
    memcpy(data + i, s, s_len);
    i += s_len;
    (*env)->ReleaseByteArrayElements(env, result, data, 0);

    return result;
}

bool asn1_der_decode(JNIEnv *env, jbyteArray sig, jbyte **r_data, size_t *r_len, jbyte **s_data, size_t *s_len) {
    size_t sig_len = (*env)->GetArrayLength(env, sig);
    jbyte *data = (*env)->GetByteArrayElements(env, sig, NULL);
    size_t i = 0;
    if (data[i++] != 0x30) {//SEQUENCE
        (*env)->ReleaseByteArrayElements(env, sig, data, JNI_ABORT);
        return false;
    }
    size_t seq_value_len = 0;
    if (!(data[i] & 0x80)) {
        seq_value_len = data[i++];
    } else {
        size_t seq_len_len = data[i++] & 0x7f;
        while (seq_len_len > 0) {
            seq_value_len |= (data[i++] << (seq_len_len - 1));
            seq_len_len--;
        }
    }

    if (data[i++] != 0x02) {//INTEGER
        (*env)->ReleaseByteArrayElements(env, sig, data, JNI_ABORT);
        return false;
    }
    size_t r_length = data[i++];
    jbyte *r_out = malloc(r_length);
    memcpy(r_out, data + i, r_length);
    i += r_length;

    if (data[i++] != 0x02) {//INTEGER
        free(r_out);
        (*env)->ReleaseByteArrayElements(env, sig, data, JNI_ABORT);
        return false;
    }
    size_t s_length = data[i++];
    jbyte *s_out = malloc(s_length);
    memcpy(s_out, data + i, s_length);
    i += s_length;

    (*env)->ReleaseByteArrayElements(env, sig, data, JNI_ABORT);
    if (i != sig_len) {
        free(r_out);
        free(s_out);
        return false;
    }

    *r_len = r_length;
    *r_data = r_out;
    *s_len = s_length;
    *s_data = s_out;
    return true;
}

char *biginteger_to_hex(JNIEnv *env, jobject big, jint bytes) {
    jmethodID to_string = (*env)->GetMethodID(env, biginteger_class, "toString", "(I)Ljava/lang/String;");
    jstring big_string = (*env)->CallObjectMethod(env, big, to_string, (jint) 16);

    jsize len = (*env)->GetStringUTFLength(env, big_string);
#if defined(__WIN32__) || defined(_MSC_VER)
    char *raw_string = _alloca(len);
#else
    char raw_string[len];
#endif
    (*env)->GetStringUTFRegion(env, big_string, 0, len, raw_string);

    char *result = calloc(bytes, 2);
    if (len >= bytes) {
        return strncpy(result, raw_string, 2*bytes);
    } else {
        jsize diff = bytes - len;
        for (jint i = 0; i < diff*2; ++i) {
            result[i] = '0';
        }
        return strncpy(result + diff*2, raw_string, 2*bytes);
    }
}