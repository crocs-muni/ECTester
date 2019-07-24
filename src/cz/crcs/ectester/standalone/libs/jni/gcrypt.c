#include "native.h"
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <gcrypt.h>
#include "c_utils.h"
#include "c_timing.h"

static jclass provider_class;


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_GcryptLib_createProvider(JNIEnv *env, jobject this){
    /* Create the custom provider. */
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Gcrypt");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    const char *running_with = gcry_check_version(GCRYPT_VERSION);
    if (!running_with) {
        return NULL;
    }
    char full_name[strlen("libgcrypt ") + strlen(running_with) + 1];
    strcpy(full_name, "libgcrypt ");
    strcat(full_name, running_with);
    jstring name = (*env)->NewStringUTF(env, full_name);
    double version = strtod(running_with, NULL);

    return (*env)->NewObject(env, provider_class, init, name, version, name);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Gcrypt_setup(JNIEnv *env, jobject this) {
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    //gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 1);
    gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    INIT_PROVIDER(env, provider_class);

    ADD_KPG(env, this, "EC", "Gcrypt");
    ADD_KA(env, this, "ECDH", "GcryptECDH");
    ADD_SIG(env, this, "NONEwithECDSA", "GcryptECDSAwithNONE");
    ADD_SIG(env, this, "SHA1withECDSA", "GcryptECDSAwithSHA1");
    ADD_SIG(env, this, "SHA224withECDSA", "GcryptECDSAwithSHA224");
    ADD_SIG(env, this, "SHA256withECDSA", "GcryptECDSAwithSHA256");
    ADD_SIG(env, this, "SHA384withECDSA", "GcryptECDSAwithSHA384");
    ADD_SIG(env, this, "SHA512withECDSA", "GcryptECDSAwithSHA512");
    ADD_SIG(env, this, "SHA1withECDDSA", "GcryptECDDSAwithSHA1");
    ADD_SIG(env, this, "SHA224withECDDSA", "GcryptECDDSAwithSHA224");
    ADD_SIG(env, this, "SHA256withECDDSA", "GcryptECDDSAwithSHA256");
    ADD_SIG(env, this, "SHA384withECDDSA", "GcryptECDDSAwithSHA384");
    ADD_SIG(env, this, "SHA512withECDDSA", "GcryptECDDSAwithSHA512");

    init_classes(env, "Gcrypt");
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_GcryptLib_getCurves(JNIEnv *env, jobject this) {
    jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);

    const char *name;
    unsigned int nbits;

    for (size_t i = 0; (name = gcry_pk_get_curve(NULL, i, &nbits)); i++){
        jstring curve_name = (*env)->NewStringUTF(env, name);
        (*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
    }

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Gcrypt_keysizeSupported(JNIEnv *env, jobject this, jint keysize) {
    const char *name;
    unsigned int nbits;

    for (size_t i = 0; (name = gcry_pk_get_curve(NULL, i, &nbits)); i++){
        if (nbits == keysize) {
            return JNI_TRUE;
        }
    }

    return JNI_FALSE;
}

/*
static void print_sexp(gcry_sexp_t sexp) {
    size_t len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char string[len];
    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, string, len);
    printf("%s\n", string);
    fflush(stdout);
}

static void print_chrray(unsigned char *arr, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x,", ((unsigned char) arr[i] & 0xff));
    }
    printf("\n");
}
*/

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Gcrypt_paramsSupported(JNIEnv *env, jobject this, jobject params) {
    if (params == NULL) {
        return JNI_FALSE;
    }

    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        return JNI_FALSE;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        gcry_sexp_t curve_sexp;
        gcry_sexp_build(&curve_sexp, NULL, "(public-key (ecc (curve %s)))", utf_name);
        unsigned int nbits;
        const char *ret_name = gcry_pk_get_curve(curve_sexp, 0, &nbits);
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        gcry_sexp_release(curve_sexp);
        return ret_name ? JNI_TRUE : JNI_FALSE;
    } else {
        return JNI_FALSE;
    }
}

static gcry_mpi_t bytearray_to_mpi(JNIEnv *env, jbyteArray array) {
    if (!array) {
        return NULL;
    }

    gcry_mpi_t result;

    size_t length = (*env)->GetArrayLength(env, array);
    jbyte data[length + 1];
    data[0] = 0;
    (*env)->GetByteArrayRegion(env, array, 0, length, data + 1);
    gcry_mpi_scan(&result, GCRYMPI_FMT_STD, data, length + 1, NULL);
    return result;
}

static jbyteArray mpi_to_bytearray0(JNIEnv *env, gcry_mpi_t mpi, size_t start, size_t len) {
    if (!mpi) {
        return NULL;
    }

    size_t mpi_len = 0;
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &mpi_len, mpi);
    if (start >= mpi_len) {
        return NULL;
    }
    if (start + len > mpi_len || len == 0) {
        len = mpi_len - start;
    }
    unsigned char buff[mpi_len];
    gcry_mpi_print(GCRYMPI_FMT_USG, buff, mpi_len, NULL, mpi);
    jbyteArray bytes = (*env)->NewByteArray(env, len);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
    memcpy(data, buff + start, len);
    (*env)->ReleaseByteArrayElements(env, bytes, data, 0);
    return bytes;
}

static jbyteArray mpi_to_bytearray(JNIEnv *env, gcry_mpi_t mpi) {
    return mpi_to_bytearray0(env, mpi, 0, 0);
}

static jobject mpi_to_biginteger(JNIEnv *env, gcry_mpi_t mpi) {
    if (!mpi) {
        return NULL;
    }

    jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
    jbyteArray bytes = mpi_to_bytearray(env, mpi);
    jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
    return result;
}

static gcry_mpi_t biginteger_to_mpi(JNIEnv *env, jobject bigint) {
    if (!bigint) {
        return NULL;
    }

    jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");
    jbyteArray byte_array = (jbyteArray) (*env)->CallObjectMethod(env, bigint, to_byte_array);
    return bytearray_to_mpi(env, byte_array);
}

static jint mpi_to_jint(gcry_mpi_t mpi) {
    jint result = 0;
    unsigned long nbits = gcry_mpi_get_nbits(mpi);
    int max_bits = sizeof(jint) * 8;
    for (size_t i = 0; i < nbits && i < max_bits; ++i) {
        if (gcry_mpi_test_bit(mpi, nbits - i - 1)) {
            result = ((result << 1) | 1);
        } else {
            result = (result << 1);
        }
    }
    return result;
}

static jobject buff_to_ecpoint(JNIEnv *env, gcry_buffer_t buff) {
    jint coord_size = (buff.len - 1) / 2;
    jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");

    jbyteArray x_bytes = (*env)->NewByteArray(env, coord_size);
    jbyte *x_data = (*env)->GetByteArrayElements(env, x_bytes, NULL);
    memcpy(x_data, ((char *) buff.data) + 1, coord_size);
    (*env)->ReleaseByteArrayElements(env, x_bytes, x_data, 0);
    jobject xi = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, x_bytes);

    jbyteArray y_bytes = (*env)->NewByteArray(env, coord_size);
    jbyte *y_data = (*env)->GetByteArrayElements(env, y_bytes, NULL);
    memcpy(y_data, ((char *) buff.data) + 1 + coord_size, coord_size);
    (*env)->ReleaseByteArrayElements(env, y_bytes, y_data, 0);
    jobject yi = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, y_bytes);

    jmethodID point_init = (*env)->GetMethodID(env, point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    return (*env)->NewObject(env, point_class, point_init, xi, yi);
}

static jobject create_ec_param_spec(JNIEnv *env, gcry_sexp_t key) {
    jobject result = NULL;
    gcry_mpi_t p, a, b, n, h;
    gcry_buffer_t g = {0};
    gcry_error_t err = gcry_sexp_extract_param(key, "ecc", "pab&g+nh", &p, &a, &b, &g, &n, &h, NULL);
    if (gcry_err_code(err) != GPG_ERR_NO_ERROR) {
        throw_new_var(env, "java/security/GeneralSecurityException", "Error exporting domain parameters. Error: %ui", gcry_err_code(err));
        goto end;
    }

    jobject pi = mpi_to_biginteger(env, p);
    jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject field = (*env)->NewObject(env, fp_field_class, fp_field_init, pi);

    jobject ai = mpi_to_biginteger(env, a);
    jobject bi = mpi_to_biginteger(env, b);

    jmethodID elliptic_curve_init = (*env)->GetMethodID(env, elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = (*env)->NewObject(env, elliptic_curve_class, elliptic_curve_init, field, ai, bi);

    jobject gen = buff_to_ecpoint(env, g);

    jobject order = mpi_to_biginteger(env, n);
    jint cofactor = mpi_to_jint(h);

    jmethodID ec_parameter_spec_init = (*env)->GetMethodID(env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    result = (*env)->NewObject(env, ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, gen, order, cofactor);

end:
    gcry_mpi_release(p);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_free(g.data);
    gcry_mpi_release(n);
    gcry_mpi_release(h);
    return result;
}

static jobject generate_from_sexp(JNIEnv *env, gcry_sexp_t gen_sexp) {
    jobject result = NULL;
    gcry_sexp_t key_sexp;

    native_timing_start();
    gcry_error_t err = gcry_pk_genkey(&key_sexp, gen_sexp);
    native_timing_stop();

    if (gcry_err_code(err) != GPG_ERR_NO_ERROR) {
        throw_new_var(env, "java/security/GeneralSecurityException", "Error generating key. Error: %ui", gcry_err_code(err));
        goto release_sexp;
    }
    gcry_sexp_t pkey = gcry_sexp_find_token(key_sexp, "public-key", 0);
    gcry_sexp_t skey = gcry_sexp_find_token(key_sexp, "private-key", 0);

    jobject ec_param_spec = create_ec_param_spec(env, skey);
    if (!ec_param_spec) {
        goto release_keypair;
    }

    gcry_buffer_t q = {0};
    gcry_mpi_t d;
    err = gcry_sexp_extract_param(skey, "ecc", "&q+d", &q, &d, NULL);

    jbyteArray pub_bytes = (*env)->NewByteArray(env, q.size);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
    memcpy(key_pub, q.data, q.size);
    (*env)->ReleaseByteArrayElements(env, pub_bytes, key_pub, 0);

	size_t priv_len = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &priv_len, d);
	jbyteArray priv_bytes = (*env)->NewByteArray(env, priv_len);
	jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
	gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) key_priv, priv_len, NULL, d);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_pub_param_spec);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    result = (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);

    gcry_mpi_release(d);
    gcry_free(q.data);

release_keypair:
	gcry_sexp_release(pkey);
	gcry_sexp_release(skey);
release_sexp:
    gcry_sexp_release(key_sexp);
    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Gcrypt_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject this, jint keysize, jobject random) {
    gcry_sexp_t gen_sexp;
    gcry_sexp_build(&gen_sexp, NULL, "(genkey (ecc (flags no-keytest param) (nbits %d)))", keysize);

    jobject result = generate_from_sexp(env, gen_sexp);
    gcry_sexp_release(gen_sexp);
    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Gcrypt_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject this, jobject params, jobject random) {
    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        return NULL;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        gcry_sexp_t gen_sexp;
        gcry_sexp_build(&gen_sexp, NULL, "(genkey (ecc (flags no-keytest param) (curve %s)))", utf_name);
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        jobject result = generate_from_sexp(env, gen_sexp);
        gcry_sexp_release(gen_sexp);
        return result;
    } else {
        return NULL;
    }
}

static gcry_sexp_t create_key(JNIEnv *env, jobject ec_param_spec, const char *key_fmt, gcry_mpi_t q, gcry_mpi_t d) {
    gcry_mpi_t p, a, b, g, n, h;

    jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject elliptic_curve = (*env)->CallObjectMethod(env, ec_param_spec, get_curve);

    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

    jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
    jint bits = (*env)->CallIntMethod(env, field, get_bits);
    jint bytes = (bits + 7) / 8;

    jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
    jobject big_a = (*env)->CallObjectMethod(env, elliptic_curve, get_a);
    a = biginteger_to_mpi(env, big_a);

    jmethodID get_b = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
    jobject big_b = (*env)->CallObjectMethod(env, elliptic_curve, get_b);
    b = biginteger_to_mpi(env, big_b);

    jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
    jobject big_p = (*env)->CallObjectMethod(env, field, get_p);
    p = biginteger_to_mpi(env, big_p);

    jmethodID get_g = (*env)->GetMethodID(env, ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
    jobject g_point = (*env)->CallObjectMethod(env, ec_param_spec, get_g);

    jmethodID get_x = (*env)->GetMethodID(env, point_class, "getAffineX", "()Ljava/math/BigInteger;");
    jobject gx = (*env)->CallObjectMethod(env, g_point, get_x);

    jmethodID get_y = (*env)->GetMethodID(env, point_class, "getAffineY", "()Ljava/math/BigInteger;");
    jobject gy = (*env)->CallObjectMethod(env, g_point, get_y);

    jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");

    jbyteArray gx_bytes = (jbyteArray) (*env)->CallObjectMethod(env, gx, to_byte_array);
    size_t gx_len = (*env)->GetArrayLength(env, gx_bytes);
    jbyteArray gy_bytes = (jbyteArray) (*env)->CallObjectMethod(env, gy, to_byte_array);
    size_t gy_len = (*env)->GetArrayLength(env, gy_bytes);
    unsigned char g_data[1 + 2 * bytes];
    g_data[0] = 0x04;
    jbyte *gx_data = (*env)->GetByteArrayElements(env, gx_bytes, NULL);
    memcpy(g_data + 1, gx_data + (gx_len - bytes), bytes);
    (*env)->ReleaseByteArrayElements(env, gx_bytes, gx_data, JNI_ABORT);
    jbyte *gy_data = (*env)->GetByteArrayElements(env, gy_bytes, NULL);
    memcpy(g_data + 1 + bytes, gy_data + (gy_len - bytes), bytes);
    (*env)->ReleaseByteArrayElements(env, gy_bytes, gy_data, JNI_ABORT);

    gcry_mpi_scan(&g, GCRYMPI_FMT_USG, g_data, 1 + 2 * bytes, NULL);

    jmethodID get_n = (*env)->GetMethodID(env, ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
    jobject big_n = (*env)->CallObjectMethod(env, ec_param_spec, get_n);
    n = biginteger_to_mpi(env, big_n);

    jmethodID get_h = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCofactor", "()I");
    jint jh = (*env)->CallIntMethod(env, ec_param_spec, get_h);
    h = gcry_mpi_set_ui(NULL, jh);
    
    gcry_sexp_t inner = NULL;
    if (q && d) {
        gcry_sexp_build(&inner, NULL, "(ecc (flags param) (p %m) (a %m) (b %m) (g %m) (n %m) (h %m) (q %M) (d %M))", p, a, b, g, n, h, q, d, NULL);
    } else if (q && !d) {
        gcry_sexp_build(&inner, NULL, "(ecc (flags param) (p %m) (a %m) (b %m) (g %m) (n %m) (h %m) (q %m))", p, a, b, g, n, h, q, NULL);
    } else if (!q && d) {
        gcry_sexp_build(&inner, NULL, "(ecc (flags param) (p %m) (a %m) (b %m) (g %m) (n %m) (h %m) (d %m))", p, a, b, g, n, h, d, NULL);
    }
    gcry_sexp_t result;
    gcry_sexp_build(&result, NULL, key_fmt, inner, NULL);
    gcry_sexp_release(inner);
    return result;
}

static gcry_sexp_t create_pubkey(JNIEnv *env, jobject ec_param_spec, jbyteArray pubkey) {
    gcry_mpi_t q = bytearray_to_mpi(env, pubkey);
    gcry_sexp_t result = create_key(env, ec_param_spec, "(public-key %S)", q, NULL);
    gcry_mpi_release(q);
    return result;
}

static gcry_sexp_t create_privkey(JNIEnv *env, jobject ec_param_spec, jbyteArray pubkey, jbyteArray privkey) {
    gcry_mpi_t q = bytearray_to_mpi(env, pubkey);
    gcry_mpi_t d = bytearray_to_mpi(env, privkey);
    gcry_sexp_t result = create_key(env, ec_param_spec, "(private-key %S)", q, d);
    gcry_mpi_release(q);
    gcry_mpi_release(d);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Gcrypt_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params) {
    jbyteArray result = NULL;
    gcry_sexp_t pub = create_pubkey(env, params, pubkey);
    gcry_mpi_t priv = bytearray_to_mpi(env, privkey);

    gcry_sexp_t enc_sexp;
    gcry_sexp_build(&enc_sexp, NULL, "(data (flags raw) (value %M))", priv, NULL);
    gcry_sexp_t res_sexp;
    // TODO: figure out why ecc_encrypt_raw takes signed representation.. Nobody uses that., everybody uses unsigned reduced mod p.

    native_timing_start();
    gcry_error_t err = gcry_pk_encrypt(&res_sexp, enc_sexp, pub);
    native_timing_stop();

    if (gcry_err_code(err) != GPG_ERR_NO_ERROR) {
        throw_new_var(env, "java/security/GeneralSecurityException", "Error performing ECDH. Error: %ui", gcry_err_code(err));
        goto end;
    }

    gcry_mpi_t derived;
    err = gcry_sexp_extract_param(res_sexp, NULL, "s", &derived, NULL);

    size_t derived_bytes;
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &derived_bytes, derived);
    size_t coord_bytes = (derived_bytes - 1) / 2;
    result = mpi_to_bytearray0(env, derived, 1, coord_bytes);

    gcry_mpi_release(derived);
end:
    gcry_sexp_release(enc_sexp);
    gcry_sexp_release(res_sexp);
    gcry_sexp_release(pub);
    gcry_mpi_release(priv);
    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Gcrypt_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

static int starts_with(const char *whole, const char *prefix) {
    return !strncmp(whole, prefix, strlen(prefix));
}

static int get_hash_algo(const char *sig_type) {
    if (starts_with(sig_type, "SHA1")) {
        return GCRY_MD_SHA1;
    } else if (starts_with(sig_type, "SHA224")) {
        return GCRY_MD_SHA224;
    } else if (starts_with(sig_type, "SHA256")) {
        return GCRY_MD_SHA256;
    } else if (starts_with(sig_type, "SHA384")) {
        return GCRY_MD_SHA384;
    } else if (starts_with(sig_type, "SHA512")) {
        return GCRY_MD_SHA512;
    } else {
        return GCRY_MD_NONE;
    }
}

static const char *get_sig_algo(const char *sig_type) {
    const char *start = strstr(sig_type, "with") + strlen("with");
    if (starts_with(start, "ECDSA")) {
        return NULL;
    } else if (starts_with(start, "ECDDSA")) {
        return "rfc6979";
    } else {
        return NULL;
    }
}

static void get_sign_data_sexp(JNIEnv *env, gcry_sexp_t *result, jobject this, jbyteArray data) {
    jclass sig_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeSignatureSpi$Gcrypt");
    jfieldID type_id = (*env)->GetFieldID(env, sig_class, "type", "Ljava/lang/String;");
    jstring type = (jstring)(*env)->GetObjectField(env, this, type_id);
    const char* type_data = (*env)->GetStringUTFChars(env, type, NULL);
    int hash_algo = get_hash_algo(type_data);
    const char *sig_algo = get_sig_algo(type_data);
    const char *with = strstr(type_data, "with");
    char hash_name[with - type_data + 1];
    memcpy(hash_name, type_data, with - type_data);
    for (size_t i = 0; i < with - type_data; ++i) {
        hash_name[i] = tolower(hash_name[i]);
    }
    hash_name[with - type_data] = 0;
    (*env)->ReleaseStringUTFChars(env, type, type_data);

    if (hash_algo == GCRY_MD_NONE) {
        gcry_mpi_t data_mpi = bytearray_to_mpi(env, data);
        gcry_sexp_build(result, NULL, "(data (flags raw param) (value %M))", data_mpi);
        gcry_mpi_release(data_mpi);
    } else {
        unsigned int hash_len = gcry_md_get_algo_dlen(hash_algo);
        size_t data_len = (*env)->GetArrayLength(env, data);
        jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
        unsigned char out_hash[hash_len];
        gcry_md_hash_buffer(hash_algo, out_hash, data_bytes, data_len);
        (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
        gcry_mpi_t hash_mpi;
        gcry_mpi_scan(&hash_mpi, GCRYMPI_FMT_USG, out_hash, hash_len, NULL);
        if (!sig_algo) {
            gcry_sexp_build(result, NULL, "(data (flags raw param) (value %M))", hash_mpi);
        } else {
            gcry_sexp_build(result, NULL, "(data (flags %s param) (hash %s %M))", sig_algo, hash_name, hash_mpi);
        }
        gcry_mpi_release(hash_mpi);
    }
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Gcrypt_sign(JNIEnv *env, jobject this, jbyteArray data, jbyteArray privkey, jobject params) {
    jbyteArray result = NULL;
    gcry_sexp_t priv_sexp = create_privkey(env, params, NULL, privkey);

    gcry_sexp_t data_sexp;
    get_sign_data_sexp(env, &data_sexp, this, data);

    gcry_sexp_t res_sexp;
    native_timing_start();
    gcry_error_t err = gcry_pk_sign(&res_sexp, data_sexp, priv_sexp);
    native_timing_stop();
    if (gcry_err_code(err) != GPG_ERR_NO_ERROR) {
        throw_new_var(env, "java/security/GeneralSecurityException", "Error performing ECDSA. Error: %ui", gcry_err_code(err));
        goto release_init;
    }

    gcry_buffer_t r_buf = {0};
    gcry_buffer_t s_buf = {0};
    err = gcry_sexp_extract_param(res_sexp, "ecdsa", "&rs", &r_buf, &s_buf, NULL);
    if (gcry_err_code(err) != GPG_ERR_NO_ERROR) {
        throw_new_var(env, "java/security/GeneralSecurityException", "Error extracting ECDSA output. Error: %ui", gcry_err_code(err));
        goto release_res;
    }
    result = asn1_der_encode(env, r_buf.data, r_buf.len, s_buf.data, s_buf.len);

    gcry_free(r_buf.data);
    gcry_free(s_buf.data);
release_res:
    gcry_sexp_release(res_sexp);
release_init:
    gcry_sexp_release(priv_sexp);
    gcry_sexp_release(data_sexp);
    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Gcrypt_verify(JNIEnv *env, jobject this, jbyteArray sig, jbyteArray data, jbyteArray pubkey, jobject params) {
    jboolean result = JNI_FALSE;
    gcry_sexp_t pub_sexp = create_pubkey(env, params, pubkey);

    gcry_sexp_t data_sexp;
    get_sign_data_sexp(env, &data_sexp, this, data);

    size_t r_len, s_len;
    jbyte *r_data, *s_data;
    bool decode = asn1_der_decode(env, sig, &r_data, &r_len, &s_data, &s_len);
    if (!decode) {
        throw_new(env, "java/security/GeneralSecurityException", "Error decoding sig.");
        goto release_init;
    }

    gcry_mpi_t r_mpi, s_mpi;
    gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_USG, r_data, r_len, NULL);
    gcry_mpi_scan(&s_mpi, GCRYMPI_FMT_USG, s_data, s_len, NULL);
    free(r_data);
    free(s_data);

    gcry_sexp_t sig_sexp;
    gcry_sexp_build(&sig_sexp, NULL, "(sig-val (ecdsa (r %M) (s %M)))", r_mpi, s_mpi);

    native_timing_start();
    gcry_error_t err = gcry_pk_verify(sig_sexp, data_sexp, pub_sexp);
    native_timing_stop();

    if (gcry_err_code(err) != GPG_ERR_NO_ERROR) {
        if (gcry_err_code(err) != GPG_ERR_BAD_SIGNATURE) {
            throw_new(env, "java/security/GeneralSecurityException", "Error verif sig.");
            goto release_init;
        }
    } else {
        result = JNI_TRUE;
    }

release_init:
    gcry_sexp_release(pub_sexp);
    gcry_sexp_release(data_sexp);
    return result;
}