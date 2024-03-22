#include "native.h"
#include <string.h>

#include <openssl/conf.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>

#include "c_utils.h"
#include "c_timing.h"


static jclass provider_class;

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_BoringsslLib_createProvider(JNIEnv *env, jobject self) {
    /* Create the custom provider. */
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Boringssl");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    jstring name =  (*env)->NewStringUTF(env, OPENSSL_VERSION_TEXT);
    long ver_hi = (OPENSSL_VERSION_NUMBER & 0xff000000L) >> 28;
    long ver_mid = (OPENSSL_VERSION_NUMBER & 0xff0000L) >> 20;
    long ver_low = (OPENSSL_VERSION_NUMBER & 0xff00L) >> 12;
    double version = (double)ver_hi + ((double)ver_mid/10) + ((double)ver_low/100);

    return (*env)->NewObject(env, provider_class, init, name, version, name);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Boringssl_setup(JNIEnv *env, jobject self) {
    ERR_load_crypto_strings();
    CRYPTO_library_init();

    INIT_PROVIDER(env, provider_class);

    ADD_KPG(env, self, "EC", "Boringssl");
    ADD_KA(env, self, "ECDH", "BoringsslECDH");
    ADD_SIG(env, self, "NONEwithECDSA", "BoringsslECDSAwithNONE");

    init_classes(env, "Boringssl");
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_BoringsslLib_getCurves(JNIEnv *env, jobject self) {
    jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);

    size_t ncurves = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve curves[ncurves];
    EC_get_builtin_curves(curves, ncurves);

    for (size_t i = 0; i < ncurves; ++i) {
        jstring curve_name = (*env)->NewStringUTF(env, OBJ_nid2sn(curves[i].nid));
        (*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
    }

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Boringssl_keysizeSupported(JNIEnv *env, jobject self, jint keysize) {
    size_t ncurves = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve curves[ncurves];
    EC_get_builtin_curves(curves, ncurves);

    for (size_t i = 0; i < ncurves; ++i) {
        EC_GROUP *curve = EC_GROUP_new_by_curve_name(curves[i].nid);
        if (EC_GROUP_get_degree(curve) == keysize) {
            EC_GROUP_free(curve);
            return JNI_TRUE;
        }
        EC_GROUP_free(curve);
    }
    return JNI_FALSE;
}

static jobject bignum_to_biginteger(JNIEnv *env, const BIGNUM *bn) {
    jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
    int size = BN_num_bytes(bn);
    jbyteArray bytes = (*env)->NewByteArray(env, size);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
    BN_bn2bin(bn, (unsigned char *) data);
    (*env)->ReleaseByteArrayElements(env, bytes, data, 0);
    jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
    return result;
}

static BIGNUM *biginteger_to_bignum(JNIEnv *env, jobject bigint) {
    jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");

    jbyteArray byte_array = (jbyteArray) (*env)->CallObjectMethod(env, bigint, to_byte_array);
    jsize byte_length = (*env)->GetArrayLength(env, byte_array);
    jbyte *byte_data = (*env)->GetByteArrayElements(env, byte_array, NULL);
    BIGNUM *result = BN_bin2bn((unsigned char *) byte_data, byte_length, NULL);
    (*env)->ReleaseByteArrayElements(env, byte_array, byte_data, JNI_ABORT);
    return result;
}

static EC_GROUP *create_curve(JNIEnv *env, jobject params) {
    jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

    if ((*env)->IsInstanceOf(env, field, f2m_field_class)) {
        return NULL;
    }

    jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
    jobject a = (*env)->CallObjectMethod(env, elliptic_curve, get_a);
    BIGNUM *a_bn = biginteger_to_bignum(env, a);

    jmethodID get_b = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
    jobject b = (*env)->CallObjectMethod(env, elliptic_curve, get_b);
    BIGNUM *b_bn = biginteger_to_bignum(env, b);

    jmethodID get_g = (*env)->GetMethodID(env, ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
    jobject g = (*env)->CallObjectMethod(env, params, get_g);

    jmethodID get_x = (*env)->GetMethodID(env, point_class, "getAffineX", "()Ljava/math/BigInteger;");
    jobject gx = (*env)->CallObjectMethod(env, g, get_x);
    BIGNUM *gx_bn = biginteger_to_bignum(env, gx);

    jmethodID get_y = (*env)->GetMethodID(env, point_class, "getAffineY", "()Ljava/math/BigInteger;");
    jobject gy = (*env)->CallObjectMethod(env, g, get_y);
    BIGNUM *gy_bn = biginteger_to_bignum(env, gy);

    EC_GROUP *result;
    EC_POINT *g_point;

    jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
    jobject p = (*env)->CallObjectMethod(env, field, get_p);

    BIGNUM *p_bn = biginteger_to_bignum(env, p);
    result = EC_GROUP_new_curve_GFp(p_bn, a_bn, b_bn, NULL);
    BN_free(p_bn);
    BN_free(a_bn);
    BN_free(b_bn);

    if (!result) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating EC_GROUP, EC_GROUP_new_curve_GFp.");
        BN_free(gx_bn); BN_free(gy_bn);
        return NULL;
    }

    g_point = EC_POINT_new(result);
    if(!EC_POINT_set_affine_coordinates_GFp(result, g_point, gx_bn, gy_bn, NULL)) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating EC_GROUP, EC_POINT_set_affine_coordinates_GFp.");
        BN_free(gx_bn); BN_free(gy_bn); EC_POINT_free(g_point); EC_GROUP_free(result);
        return NULL;
    }

    jmethodID get_n = (*env)->GetMethodID(env, ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
    jobject n = (*env)->CallObjectMethod(env, params, get_n);
    BIGNUM *n_bn = biginteger_to_bignum(env, n);

    jmethodID get_h = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCofactor", "()I");
    jint h = (*env)->CallIntMethod(env, params, get_h);
    BIGNUM *h_bn = BN_new();
    BN_set_word(h_bn, h);

    if (!EC_GROUP_set_generator(result, g_point, n_bn, h_bn)) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating EC_GROUP, EC_GROUP_set_generator.");
        BN_free(n_bn); BN_free(h_bn); BN_free(gx_bn); BN_free(gy_bn); EC_POINT_free(g_point); EC_GROUP_free(result);
        return NULL;
    }

    EC_POINT_free(g_point);
    BN_free(gx_bn);
    BN_free(gy_bn);
    BN_free(n_bn);
    BN_free(h_bn);

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Boringssl_paramsSupported(JNIEnv *env, jobject self, jobject params){
    if (params == NULL) {
        return JNI_FALSE;
    }

    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        EC_GROUP *curve = create_curve(env, params);
        jboolean result = !curve;
        EC_GROUP_free(curve);
        return result;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        size_t ncurves = EC_get_builtin_curves(NULL, 0);
        EC_builtin_curve curves[ncurves];
        EC_get_builtin_curves(curves, ncurves);
        for (size_t i = 0; i < ncurves; ++i) {
            if (strcasecmp(utf_name, OBJ_nid2sn(curves[i].nid)) == 0) {
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

static jobject create_ec_param_spec(JNIEnv *env, const EC_GROUP *curve) {
    BIGNUM *a;
    BIGNUM *b;

    BIGNUM *gx;
    BIGNUM *gy;
    jobject field;

    BIGNUM *p = BN_new();
    a = BN_new();
    b = BN_new();
    if (!EC_GROUP_get_curve_GFp(curve, p, a, b, NULL)) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating ECParameterSpec, EC_GROUP_get_curve_GFp.");
        BN_free(p); BN_free(a); BN_free(b);
        return NULL;
    }

    jobject p_int = bignum_to_biginteger(env, p);

    jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    field = (*env)->NewObject(env, fp_field_class, fp_field_init, p_int);

    BN_free(p);

    gx = BN_new();
    gy = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(curve, EC_GROUP_get0_generator(curve), gx, gy, NULL)) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating ECParameterSpec, EC_POINT_get_affine_coordinates_GFp.");
        BN_free(a); BN_free(b); BN_free(gx); BN_free(gy);
        return NULL;
    }

    jobject a_int = bignum_to_biginteger(env, a);
    jobject b_int = bignum_to_biginteger(env, b);

    jmethodID elliptic_curve_init = (*env)->GetMethodID(env, elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = (*env)->NewObject(env, elliptic_curve_class, elliptic_curve_init, field, a_int, b_int);

    BN_free(a);
    BN_free(b);

    jobject gx_int = bignum_to_biginteger(env, gx);
    jobject gy_int = bignum_to_biginteger(env, gy);

    BN_free(gx);
    BN_free(gy);

    jmethodID point_init = (*env)->GetMethodID(env, point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject g = (*env)->NewObject(env, point_class, point_init, gx_int, gy_int);

    jobject order = bignum_to_biginteger(env, EC_GROUP_get0_order(curve));
    BIGNUM *h = BN_new();
    EC_GROUP_get_cofactor(curve, h, NULL);
    jint cofactor = BN_get_word(h);
    BN_free(h);

    jmethodID ec_parameter_spec_init = (*env)->GetMethodID(env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    return (*env)->NewObject(env, ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, order, cofactor);
}

static jobject generate_from_curve(JNIEnv *env, const EC_GROUP *curve) {
    jint keysize = EC_GROUP_get_degree(curve);
    unsigned long key_bytes = (keysize + 7) / 8;

    EC_KEY *key = EC_KEY_new();
    EC_KEY_set_group(key, curve);

    native_timing_start();
    int err = EC_KEY_generate_key(key);
    native_timing_stop();

    if (!err) {
        throw_new(env, "java/security/GeneralSecurityException", "Error generating key, EC_KEY_generate_key.");
        EC_KEY_free(key);
        return NULL;
    }

    jbyteArray priv_bytes = (*env)->NewByteArray(env, key_bytes);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
    BN_bn2bin_padded((unsigned char *) key_priv, key_bytes, EC_KEY_get0_private_key(key));
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

    unsigned long key_len = 2*key_bytes + 1;
    jbyteArray pub_bytes = (*env)->NewByteArray(env, key_len);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
    EC_POINT_point2oct(curve, EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, (unsigned char *) key_pub, key_len, NULL);
    (*env)->ReleaseByteArrayElements(env, pub_bytes, key_pub, 0);

    EC_KEY_free(key);

    jobject ec_param_spec = create_ec_param_spec(env, curve);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_pub_param_spec);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Boringssl_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random) {
    size_t ncurves = EC_get_builtin_curves(NULL, 0);
    EC_builtin_curve curves[ncurves];
    EC_get_builtin_curves(curves, ncurves);

    EC_GROUP *curve = NULL;
    for (size_t i = 0; i < ncurves; ++i) {
        curve = EC_GROUP_new_by_curve_name(curves[i].nid);
        if (EC_GROUP_get_degree(curve) == keysize) {
            break;
        }
        EC_GROUP_free(curve);
    }

    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
        return NULL;
    }

    jobject result = generate_from_curve(env, curve);
    EC_GROUP_free(curve);
    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Boringssl_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random) {
    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        EC_GROUP *curve = create_curve(env, params);
        jobject result = generate_from_curve(env, curve);
        EC_GROUP_free(curve);
        return result;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        size_t ncurves = EC_get_builtin_curves(NULL, 0);
        EC_builtin_curve curves[ncurves];
        EC_get_builtin_curves(curves, ncurves);
        EC_GROUP *curve = NULL;
        for (size_t i = 0; i < ncurves; ++i) {
            if (strcasecmp(utf_name, OBJ_nid2sn(curves[i].nid)) == 0) {
                curve = EC_GROUP_new_by_curve_name(curves[i].nid);
                break;
            }
        }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        if (!curve) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
            return NULL;
        }
        jobject result = generate_from_curve(env, curve);
        EC_GROUP_free(curve);
        return result;
    } else {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return NULL;
    }
}

EC_KEY *barray_to_pubkey(JNIEnv *env, const EC_GROUP *curve, jbyteArray pub) {
    EC_KEY *result = EC_KEY_new();
    EC_KEY_set_group(result, curve);
    jsize pub_len = (*env)->GetArrayLength(env, pub);
    jbyte *pub_data = (*env)->GetByteArrayElements(env, pub, NULL);
    EC_POINT *pub_point = EC_POINT_new(curve);
    EC_POINT_oct2point(curve, pub_point, (unsigned char *) pub_data, pub_len, NULL);
    (*env)->ReleaseByteArrayElements(env, pub, pub_data, JNI_ABORT);
    EC_KEY_set_public_key(result, pub_point);
    EC_POINT_free(pub_point);
    return result;
}

EC_KEY *barray_to_privkey(JNIEnv *env,  const EC_GROUP *curve, jbyteArray priv) {
    EC_KEY *result = EC_KEY_new();
    EC_KEY_set_group(result, curve);
    jsize priv_len = (*env)->GetArrayLength(env, priv);
    jbyte *priv_data = (*env)->GetByteArrayElements(env, priv, NULL);
    BIGNUM *s = BN_bin2bn((unsigned char *) priv_data, priv_len, NULL);
    (*env)->ReleaseByteArrayElements(env, priv, priv_data, JNI_ABORT);
    EC_KEY_set_private_key(result, s);
    BN_free(s);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Boringssl_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params) {
    EC_GROUP *curve = create_curve(env, params);
    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return NULL;
    }

    EC_KEY *pub = barray_to_pubkey(env, curve, pubkey);
    EC_KEY *priv = barray_to_privkey(env, curve, privkey);

    int field_size = EC_GROUP_get_degree(curve);
    size_t secret_len = (field_size + 7)/8;

    //TODO: Do more KeyAgreements here, but will have to do the hash-fun manually,
    //      probably using the ECDH_KDF_X9_62 by wrapping it and dynamically choosing the EVP_MD. from the type string.
    jbyteArray result = (*env)->NewByteArray(env, secret_len);
    jbyte *result_data = (*env)->GetByteArrayElements(env, result, NULL);

    native_timing_start();
    int err = ECDH_compute_key(result_data, secret_len, EC_KEY_get0_public_key(pub), priv, NULL);
    native_timing_stop();

    if (err <= 0) {
        throw_new(env, "java/security/GeneralSecurityException", "Error computing ECDH, ECDH_compute_key.");
        EC_KEY_free(pub); EC_KEY_free(priv); EC_GROUP_free(curve);
        (*env)->ReleaseByteArrayElements(env, result, result_data, JNI_ABORT);
        return NULL;
    }
    (*env)->ReleaseByteArrayElements(env, result, result_data, 0);

    EC_KEY_free(pub);
    EC_KEY_free(priv);
    EC_GROUP_free(curve);
    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Boringssl_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Boringssl_sign(JNIEnv *env, jobject self, jbyteArray data, jbyteArray privkey, jobject params) {
    EC_GROUP *curve = create_curve(env, params);
    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return NULL;
    }

    EC_KEY *priv = barray_to_privkey(env, curve, privkey);

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);
    // TODO: Do more Signatures here, maybe use the EVP interface to get to the hashes easier and not hash manually?

    native_timing_start();
    ECDSA_SIG *signature = ECDSA_do_sign((unsigned char *) data_data, data_size, priv);
    native_timing_stop();

    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    if (!signature) {
        throw_new(env, "java/security/GeneralSecurityException", "Error signing, ECDSA_do_sign.");
        EC_KEY_free(priv); EC_GROUP_free(curve);
        return NULL;
    }

    jsize sig_len = i2d_ECDSA_SIG(signature, NULL);
    jbyteArray result = (*env)->NewByteArray(env, sig_len);
    jbyte *result_data = (*env)->GetByteArrayElements(env, result, NULL);
    jbyte *result_data_ptr = result_data;
    i2d_ECDSA_SIG(signature, (unsigned char **)&result_data_ptr);
    (*env)->ReleaseByteArrayElements(env, result, result_data, 0);

    ECDSA_SIG_free(signature);
    EC_KEY_free(priv);
    EC_GROUP_free(curve);
    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Boringssl_verify(JNIEnv *env, jobject self, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
    EC_GROUP *curve = create_curve(env, params);
    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return JNI_FALSE;
    }

    EC_KEY *pub = barray_to_pubkey(env, curve, pubkey);

    jsize sig_len = (*env)->GetArrayLength(env, signature);
    jbyte *sig_data = (*env)->GetByteArrayElements(env, signature, NULL);
    jbyte *sig_data_ptr = sig_data;
    ECDSA_SIG *sig_obj = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sig_data_ptr, sig_len);
    (*env)->ReleaseByteArrayElements(env, signature, sig_data, JNI_ABORT);

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);

    native_timing_start();
    int result = ECDSA_do_verify((unsigned char *) data_data, data_size, sig_obj, pub);
    native_timing_stop();

    if (result < 0) {
        throw_new(env, "java/security/GeneralSecurityException", "Error verifying, ECDSA_do_verify.");
        EC_KEY_free(pub); EC_GROUP_free(curve); ECDSA_SIG_free(sig_obj);
        (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
        return JNI_FALSE;
    }
    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);

    ECDSA_SIG_free(sig_obj);
    EC_KEY_free(pub);
    EC_GROUP_free(curve);
    return (result == 1) ? JNI_TRUE : JNI_FALSE;
}