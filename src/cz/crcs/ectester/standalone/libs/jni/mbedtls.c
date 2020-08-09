#include "native.h"
#include <string.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/version.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <stdio.h>

#include "c_utils.h"
#include "c_timing.h"

static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static jclass provider_class;


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MbedTLSLib_createProvider(JNIEnv *env, jobject this) {
    /* Create the custom provider. */
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$MbedTLS");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    jstring name =  (*env)->NewStringUTF(env, MBEDTLS_VERSION_STRING_FULL);
    double version = MBEDTLS_VERSION_MAJOR + (MBEDTLS_VERSION_MINOR/10) + (MBEDTLS_VERSION_PATCH/100);

    return (*env)->NewObject(env, provider_class, init, name, version, name);
}

static int dev_urandom(void *data, unsigned char *output, size_t len, size_t *olen) {
    FILE *file;
    size_t ret, left = len;
    unsigned char *p = output;
    ((void) data);

    *olen = 0;

    file = fopen( "/dev/urandom", "rb" );
    if (file == NULL) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    while (left > 0) {
       ret = fread(p, 1, left, file);
       if (ret == 0 && ferror(file)) {
           fclose(file);
           return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
       }

       p += ret;
       left -= ret;
    }
    fclose(file);
    *olen = len;

    return 0;
}

static int ctr_drbg_wrapper(void *ctx, unsigned char *buf, size_t len) {
    native_timing_pause();
    int result = mbedtls_ctr_drbg_random(ctx, buf, len);
    native_timing_restart();
    return result;
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024MbedTLS_setup(JNIEnv *env, jobject this) {
    INIT_PROVIDER(env, provider_class);

    ADD_KPG(env, this, "EC", "MbedTLS");
    ADD_KA(env, this, "ECDH", "MbedTLSECDH");
    ADD_SIG(env, this, "NONEwithECDSA", "MbedTLSECDSAwithNONE");

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_entropy_add_source(&entropy, dev_urandom, NULL, 32, MBEDTLS_ENTROPY_SOURCE_STRONG);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    init_classes(env, "MbedTLS");
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MbedTLSLib_getCurves(JNIEnv *env, jobject this) {
    jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);
    for (const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {

        jstring curve_name = (*env)->NewStringUTF(env, curve_info->name);
        (*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
    }
    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024MbedTLS_keysizeSupported(JNIEnv *env, jobject this, jint keysize) {
    for (const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (keysize == curve_info->bit_size) {
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024MbedTLS_paramsSupported(JNIEnv *env, jobject this, jobject params) {
    if (params == NULL) {
        return JNI_FALSE;
    }

    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
        jobject curve = (*env)->CallObjectMethod(env, params, get_curve);

        jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
        jobject field = (*env)->CallObjectMethod(env, curve, get_field);
        if ((*env)->IsInstanceOf(env, field, f2m_field_class)) {
            return JNI_FALSE;
        }
        return JNI_TRUE;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        for (const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++) {
            if (strcasecmp(utf_name, curve_info->name) == 0) {
                (*env)->ReleaseStringUTFChars(env, name, utf_name);
                return JNI_TRUE;
            }
        }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        return JNI_FALSE;
    } else {
        return JNI_FALSE;
    }
}

const char *err_to_string(int error) {
    switch (error) {
        case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
            return "Bad input parameters to function.";
        case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
            return "The buffer is too small to write to.";
        case MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE:
            return "The requested feature is not available, for example, the requested curve is not supported.";
        case MBEDTLS_ERR_ECP_VERIFY_FAILED:
            return "The signature is not valid.";
        case MBEDTLS_ERR_ECP_ALLOC_FAILED:
            return "Memory allocation failed.";
        case MBEDTLS_ERR_ECP_RANDOM_FAILED:
            return "Generation of random value, such as ephemeral key, failed.";
        case MBEDTLS_ERR_ECP_INVALID_KEY:
            return "Invalid private or public key.";
        case MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:
            return "The buffer contains a valid signature followed by more data.";
        case MBEDTLS_ERR_MPI_FILE_IO_ERROR:
            return "An error occurred while reading from or writing to a file.";
        case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
            return "Bad input parameters to function.";
        case MBEDTLS_ERR_MPI_INVALID_CHARACTER:
            return "There is an invalid character in the digit string.";
        case MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
            return "The buffer is too small to write to.";
        case MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
            return "The input arguments are negative or result in illegal output.";
        case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
            return "The input argument for division is zero, which is not allowed.";
        case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
            return "The input arguments are not acceptable.";
        case MBEDTLS_ERR_MPI_ALLOC_FAILED:
            return "Memory allocation failed.";
        default:
            return "UNKNOWN.";
    }
}

static jobject biginteger_from_mpi(JNIEnv *env, const mbedtls_mpi *mpi) {
    jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
    size_t size = mbedtls_mpi_size(mpi);
    jbyteArray bytes = (*env)->NewByteArray(env, size);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
    mbedtls_mpi_write_binary(mpi, (unsigned char *) data, size);
    (*env)->ReleaseByteArrayElements(env, bytes, data, 0);
    jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
    return result;
}

static void mpi_from_biginteger(JNIEnv* env, jobject biginteger, mbedtls_mpi *mpi) {
    jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");

    jbyteArray byte_array = (jbyteArray) (*env)->CallObjectMethod(env, biginteger, to_byte_array);
    jsize byte_length = (*env)->GetArrayLength(env, byte_array);
    jbyte *byte_data = (*env)->GetByteArrayElements(env, byte_array, NULL);
    mbedtls_mpi_read_binary(mpi, (unsigned char *) byte_data, byte_length);
    (*env)->ReleaseByteArrayElements(env, byte_array, byte_data, JNI_ABORT);
}

static jobject create_ec_param_spec(JNIEnv *env, const mbedtls_ecp_group *group) {
    jobject p = biginteger_from_mpi(env, &group->P);
    jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject field = (*env)->NewObject(env, fp_field_class, fp_field_init, p);

    jobject a;
    if (group->A.p == NULL) {
        jmethodID biginteger_subtract = (*env)->GetMethodID(env, biginteger_class, "subtract", "(Ljava/math/BigInteger;)Ljava/math/BigInteger;");
        jmethodID biginteger_valueof = (*env)->GetStaticMethodID(env, biginteger_class, "valueOf", "(J)Ljava/math/BigInteger;");
        jobject three = (*env)->CallStaticObjectMethod(env, biginteger_class, biginteger_valueof, (jlong) 3);
        a = (*env)->CallObjectMethod(env, p, biginteger_subtract, three);
    } else {
        a = biginteger_from_mpi(env, &group->A);
    }
    jobject b = biginteger_from_mpi(env, &group->B);

    jmethodID elliptic_curve_init = (*env)->GetMethodID(env, elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = (*env)->NewObject(env, elliptic_curve_class, elliptic_curve_init, field, a, b);

    jobject gx = biginteger_from_mpi(env, &group->G.X);
    jobject gy = biginteger_from_mpi(env, &group->G.Y);
    jmethodID point_init = (*env)->GetMethodID(env, point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject g = (*env)->NewObject(env, point_class, point_init, gx, gy);

    jobject n = biginteger_from_mpi(env, &group->N);
    jint h = 1;

    jmethodID ec_parameter_spec_init = (*env)->GetMethodID(env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    return (*env)->NewObject(env, ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, n, h);
}

static void create_curve(JNIEnv *env, jobject params, mbedtls_ecp_group *group) {
    mbedtls_ecp_group_init(group);
    group->id = 0;

    jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject curve = (*env)->CallObjectMethod(env, params, get_curve);

    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, curve, get_field);

    jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
    jobject p = (*env)->CallObjectMethod(env, field, get_p);
    mpi_from_biginteger(env, p, &group->P);

    jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
    jobject a = (*env)->CallObjectMethod(env, curve, get_a);
    mpi_from_biginteger(env, a, &group->A);

    jmethodID get_b = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
    jobject b = (*env)->CallObjectMethod(env, curve, get_b);
    mpi_from_biginteger(env, b, &group->B);

    jmethodID get_g = (*env)->GetMethodID(env, ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
    jobject g = (*env)->CallObjectMethod(env, params, get_g);

    jmethodID get_x = (*env)->GetMethodID(env, point_class, "getAffineX", "()Ljava/math/BigInteger;");
    jobject gx = (*env)->CallObjectMethod(env, g, get_x);
    mpi_from_biginteger(env, gx, &group->G.X);

    jmethodID get_y = (*env)->GetMethodID(env, point_class, "getAffineY", "()Ljava/math/BigInteger;");
    jobject gy = (*env)->CallObjectMethod(env, g, get_y);
    mpi_from_biginteger(env, gy, &group->G.Y);

    mbedtls_mpi_lset(&group->G.Z, 1);

    jmethodID get_n = (*env)->GetMethodID(env, ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
    jobject n = (*env)->CallObjectMethod(env, params, get_n);
    mpi_from_biginteger(env, n, &group->N);
    group->pbits = group->nbits = mbedtls_mpi_bitlen(&group->P);
    group->h = 0;
}

static jobject generate_from_curve(JNIEnv *env, mbedtls_ecp_group *group) {
    mbedtls_mpi d;
    mbedtls_mpi_init(&d);

    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    if (ctr_drbg.reseed_counter >= ctr_drbg.reseed_interval) {
        // Reseed manually, outside of the timing window, to not disturb the timing data.
        // They are somewhat disturbed anyway, but we cannot really get rid of that easily.
        // We also help it by using a wrapper and pausing for random gen.
        mbedtls_ctr_drbg_reseed(&ctr_drbg, NULL, 0);
    }

    native_timing_start();
    int error = mbedtls_ecp_gen_keypair(group, &d, &Q, ctr_drbg_wrapper, &ctr_drbg);
    native_timing_stop();

    if (error) {
        throw_new(env, "java/security/GeneralSecurityException", err_to_string(error));
        mbedtls_mpi_free(&d);
        mbedtls_ecp_point_free(&Q);
        return NULL;
    }

    jint keysize = (jint) mbedtls_mpi_bitlen(&group->N);
    unsigned long key_bytes = (keysize + 7) / 8;
    jbyteArray priv_bytes = (*env)->NewByteArray(env, key_bytes);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
    mbedtls_mpi_write_binary(&d, (unsigned char *) key_priv, key_bytes);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

    unsigned long key_len = 2*key_bytes + 1;
    jbyteArray pub_bytes = (*env)->NewByteArray(env, key_len);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
    size_t out_key_len = 0;
    mbedtls_ecp_point_write_binary(group, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &out_key_len, (unsigned char *) key_pub, key_len);
    (*env)->ReleaseByteArrayElements(env, pub_bytes, key_pub, 0);

    jobject ec_param_spec = create_ec_param_spec(env, group);

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_pub_param_spec);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

static jobject generate_from_curve_info(JNIEnv *env, const mbedtls_ecp_curve_info *curve) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, curve->grp_id);
    jobject result = generate_from_curve(env, &group);
    mbedtls_ecp_group_free(&group);
    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024MbedTLS_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject this, jint keysize, jobject random) {
    const mbedtls_ecp_curve_info *curve = NULL;
    for (const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (keysize == curve_info->bit_size) {
            curve = curve_info;
            break;
        }
    }

    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
        return NULL;
    }

    return generate_from_curve_info(env, curve);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024MbedTLS_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject this, jobject params, jobject random) {
    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        mbedtls_ecp_group curve;
        create_curve(env, params, &curve);
        jobject result = generate_from_curve(env, &curve);
        mbedtls_ecp_group_free(&curve);
        return result;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        const mbedtls_ecp_curve_info *curve = NULL;
        for (const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++) {
            if (strcasecmp(utf_name, curve_info->name) == 0) {
                (*env)->ReleaseStringUTFChars(env, name, utf_name);
                curve = curve_info;
                break;
            }
        }
        if (!curve) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
            (*env)->ReleaseStringUTFChars(env, name, utf_name);
            return NULL;
        }
        return generate_from_curve_info(env, curve);
    } else {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return NULL;
    }
}

static void create_pubkey(JNIEnv *env, jbyteArray pubkey, mbedtls_ecp_group *curve, mbedtls_ecp_point *pub) {
    mbedtls_ecp_point_init(pub);
    jsize pub_size = (*env)->GetArrayLength(env, pubkey);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pubkey, NULL);
    mbedtls_ecp_point_read_binary(curve, pub, (unsigned char *) key_pub, pub_size);
    (*env)->ReleaseByteArrayElements(env, pubkey, key_pub, JNI_ABORT);
}

static void create_privkey(JNIEnv *env, jbyteArray privkey, mbedtls_mpi *priv) {
    mbedtls_mpi_init(priv);
    jsize priv_size = (*env)->GetArrayLength(env, privkey);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, privkey, NULL);
    mbedtls_mpi_read_binary(priv, (unsigned char *) key_priv, priv_size);
    (*env)->ReleaseByteArrayElements(env, privkey, key_priv, JNI_ABORT);
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024MbedTLS_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params) {
    mbedtls_ecp_group curve;
    create_curve(env, params, &curve);

    mbedtls_ecp_point pub;
    create_pubkey(env, pubkey, &curve, &pub);

    mbedtls_mpi priv;
    create_privkey(env, privkey, &priv);

    mbedtls_mpi result;
    mbedtls_mpi_init(&result);

    native_timing_start();
    int error = mbedtls_ecdh_compute_shared(&curve, &result, &pub, &priv, ctr_drbg_wrapper, &ctr_drbg);
    native_timing_stop();

    if (error) {
        throw_new(env, "java/security/GeneralSecurityException", err_to_string(error));
        mbedtls_mpi_free(&result);
        mbedtls_mpi_free(&priv);
        mbedtls_ecp_point_free(&pub);
        mbedtls_ecp_group_free(&curve);
        return NULL;
    }

    jint keysize = (jint) mbedtls_mpi_bitlen(&curve.N);
    unsigned long key_bytes = (keysize + 7) / 8;
    jbyteArray result_bytes = (*env)->NewByteArray(env, key_bytes);
    jbyte *result_data = (*env)->GetByteArrayElements(env, result_bytes, NULL);
    mbedtls_mpi_write_binary(&result, (unsigned char *) result_data, key_bytes);
    (*env)->ReleaseByteArrayElements(env, result_bytes, result_data, 0);

    mbedtls_mpi_free(&result);
    mbedtls_mpi_free(&priv);
    mbedtls_ecp_point_free(&pub);
    mbedtls_ecp_group_free(&curve);

    return result_bytes;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024MbedTLS_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algo) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024MbedTLS_sign(JNIEnv *env, jobject this, jbyteArray data, jbyteArray privkey, jobject params) {
    mbedtls_ecp_group curve;
    create_curve(env, params, &curve);

    mbedtls_mpi priv;
    create_privkey(env, privkey, &priv);

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);

    native_timing_start();
    int error = mbedtls_ecdsa_sign(&curve, &r, &s, &priv, (unsigned char *) data_data, data_size, ctr_drbg_wrapper, &ctr_drbg);
    native_timing_stop();

    mbedtls_mpi_free(&priv);
    mbedtls_ecp_group_free(&curve);
    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    if (error) {
        throw_new(env, "java/security/GeneralSecurityException", err_to_string(error));
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        return NULL;
    }

    jsize rlen = (mbedtls_mpi_bitlen(&r) + 7) / 8;
    jbyte r_bytes[rlen];
    mbedtls_mpi_write_binary(&r, (unsigned char *) r_bytes, rlen);
    jsize slen = (mbedtls_mpi_bitlen(&s) + 7) / 8;
    jbyte s_bytes[slen];
    mbedtls_mpi_write_binary(&s, (unsigned char *) s_bytes, slen);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return asn1_der_encode(env, r_bytes, rlen, s_bytes, slen);
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024MbedTLS_verify(JNIEnv *env, jobject this, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
    mbedtls_ecp_group curve;
    create_curve(env, params, &curve);

    mbedtls_ecp_point pub;
    create_pubkey(env, pubkey, &curve, &pub);
    jbyte *r_bytes;
    size_t rlen;
    jbyte *s_bytes;
    size_t slen;
    bool decode = asn1_der_decode(env, signature, &r_bytes, &rlen, &s_bytes, &slen);
    if (!decode) {
        throw_new(env, "java/security/GeneralSecurityException", "Error decoding sig.");
        mbedtls_ecp_point_free(&pub);
        mbedtls_ecp_group_free(&curve);
        return JNI_FALSE;
    }

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_read_binary(&r, (unsigned char *) r_bytes, rlen);
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary(&s, (unsigned char *) s_bytes, slen);
    free(r_bytes);
    free(s_bytes);

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);

    native_timing_start();
    int error = mbedtls_ecdsa_verify(&curve, (unsigned char *) data_data, data_size, &pub, &r, &s);
    native_timing_stop();

    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    if (error) {
        if (error != MBEDTLS_ERR_ECP_VERIFY_FAILED) {
            throw_new(env, "java/security/GeneralSecurityException", err_to_string(error));
        }
        mbedtls_ecp_point_free(&pub);
        mbedtls_ecp_group_free(&curve);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}