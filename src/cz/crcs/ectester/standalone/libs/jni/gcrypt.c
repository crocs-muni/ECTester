#include "native.h"
#include <stdio.h>
#include <gcrypt.h>
#include "c_utils.h"

static jclass provider_class;


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_GcryptLib_createProvider(JNIEnv *env, jobject this){
    /* Create the custom provider. */
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Gcrypt");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    const char *built_with = GCRYPT_VERSION;
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
    //ADD_KA(env, self, "ECDH", "OpensslECDH");
    //ADD_SIG(env, self, "NONEwithECDSA", "OpensslECDSAwithNONE");

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

static void print_sexp(gcry_sexp_t sexp) {
    size_t len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char string[len];
    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, string, len);
    printf("%s\n", string);
    fflush(stdout);
}

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

static jobject mpi_to_biginteger(JNIEnv *env, gcry_mpi_t mpi) {
    jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
	size_t len = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &len, mpi);
	jbyteArray bytes = (*env)->NewByteArray(env, len);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
    gcry_mpi_print(GCRYMPI_FMT_USG, data, len, &len, mpi);
    (*env)->ReleaseByteArrayElements(env, bytes, data, 0);
    jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
    return result;
}

static gcry_mpi_t biginteger_to_mpi(JNIEnv *env, jobject bigint) {
    jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");

    jbyteArray byte_array = (jbyteArray) (*env)->CallObjectMethod(env, bigint, to_byte_array);
    jsize byte_length = (*env)->GetArrayLength(env, byte_array);
    jbyte *byte_data = (*env)->GetByteArrayElements(env, byte_array, NULL);
    gcry_mpi_t result;
    gcry_mpi_scan(&result, GCRYMPI_FMT_USG, byte_data, byte_length, NULL);
    (*env)->ReleaseByteArrayElements(env, byte_array, byte_data, JNI_ABORT);
    return result;
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
    jint coord_size = (buff.size - 1) / 2;
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
    gcry_error_t err = gcry_pk_genkey(&key_sexp, gen_sexp);
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
	gcry_mpi_print(GCRYMPI_FMT_USG, key_priv, priv_len, NULL, d);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_param_spec);

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