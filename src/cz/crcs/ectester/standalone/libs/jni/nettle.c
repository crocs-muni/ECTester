#include "native.h"
#include <string.h>

#include <nettle/version.h>
#include <nettle/ecc.h>
#include <nettle/ecc-curve.h>
#include <nettle/ecdsa.h>
#include <nettle/yarrow.h>
#include <gmp.h>
#include <fcntl.h>
#include <unistd.h>

#include "c_utils.h"
#include "c_timing.h"



static jclass provider_class;

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_NettleLib_createProvider(JNIEnv *env, jobject self) {
    /* Create the custom provider. */
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Nettle");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    jstring name =  (*env)->NewStringUTF(env, "Nettle");

    double version = NETTLE_VERSION_MAJOR + (double) NETTLE_VERSION_MINOR / 10;
    return (*env)->NewObject(env, provider_class, init, name, version, name);

}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Nettle_setup(JNIEnv *env, jobject self) {

    INIT_PROVIDER(env, provider_class);
    ADD_KPG(env, self, "EC", "Nettle");
    ADD_KPG(env, self, "ECDSA", "Openssl");
    ADD_SIG(env, self, "ECDSA", "NettleECDSA");

    init_classes(env, "Nettle");

}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_NettleLib_getCurves(JNIEnv *env, jobject self) {
    jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);
    char *curve_names[] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1", "Curve25519"};
    for (int i = 0; i < 6; i++) {
        jstring curve_name = (*env)->NewStringUTF(env, curve_names[i]);
        (*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
    }
    
    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_keysizeSupported(JNIEnv *env, jobject self, jint keysize) {
    int supported[] = {24, 28, 32, 48, 66};
    for (int i = 0; i < 5; i++) {
        if (keysize == supported[i])
            return JNI_TRUE;
    }

    return JNI_TRUE;
}

static jobject mpz_to_biginteger(JNIEnv *env, const mpz_t* mp) {
    jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
    size_t size;
    mpz_export(NULL, &size, 1, sizeof(unsigned char), 0, 0, *mp);
    jbyteArray bytes = (*env)->NewByteArray(env, size);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL); 
    mpz_export(data, &size, 1, sizeof(unsigned char), 0, 0, *mp);
    (*env)->ReleaseByteArrayElements(env, bytes, data, 0);
    jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
    return result;
}

static void biginteger_to_mpz(JNIEnv *env, jobject bigint, mpz_t* mp) {
    jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");

    jbyteArray byte_array = (jbyteArray) (*env)->CallObjectMethod(env, bigint, to_byte_array);
    jsize byte_length = (*env)->GetArrayLength(env, byte_array);
    jbyte *byte_data = (*env)->GetByteArrayElements(env, byte_array, NULL);
    mpz_import(*mp, byte_length, 1, sizeof(unsigned char), 0, 0, byte_data);
    (*env)->ReleaseByteArrayElements(env, byte_array, byte_data, JNI_ABORT);
}

static const struct ecc_curve* create_curve(JNIEnv *env, jobject params, const char* curve_name) {
    printf("AND NOW THIS \n");
    const struct ecc_curve* curve = NULL;
    printf("AND NOW THIS \n");
    if (curve_name) {
        if (strcasecmp("secp256r1", curve_name) == 0) {
            curve = nettle_get_secp_256r1();
        }
        return curve;
    }

    jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);


    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

    jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
    jobject a = (*env)->CallObjectMethod(env, elliptic_curve, get_a);

    jmethodID get_b = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
    jobject b = (*env)->CallObjectMethod(env, elliptic_curve, get_b);

    jmethodID get_g = (*env)->GetMethodID(env, ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
    jobject g = (*env)->CallObjectMethod(env, params, get_g);

    jmethodID get_x = (*env)->GetMethodID(env, point_class, "getAffineX", "()Ljava/math/BigInteger;");
    jobject gx = (*env)->CallObjectMethod(env, g, get_x);
    mpz_t x;
    mpz_init(x);
    biginteger_to_mpz(env, gx, &x);

    jmethodID get_y = (*env)->GetMethodID(env, point_class, "getAffineY", "()Ljava/math/BigInteger;");
    jobject gy = (*env)->CallObjectMethod(env, g, get_y);

    mpz_t y;
    mpz_init(y);
    biginteger_to_mpz(env, gy, &y);

    struct ecc_point *g_point;
    struct ecc_curve *result;

    if ((*env)->IsInstanceOf(env, field, fp_field_class)) {

        struct ecc_point *g_point;
        struct ecc_curve *result;
        jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
        jobject p = (*env)->CallObjectMethod(env, field, get_p);
        mpz_t cp;
        mpz_init(cp);
        biginteger_to_mpz(env, p, &cp);

        if (!result) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating EC_GROUP, EC_GROUP_new_curve_GFp.");
            return NULL;
        }
        return NULL;
/*
        g_point = EC_POINT_new(result);
        if(!EC_POINT_set_affine_coordinates_GFp(result, g_point, gx_bn, gy_bn, NULL)) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating EC_GROUP, EC_POINT_set_affine_coordinates_GFp.");
            return NULL;
        }
*/
    } else if ((*env)->IsInstanceOf(env, field, f2m_field_class)) {
        return NULL;
    } else {
        return NULL;
    }
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_paramsSupported(JNIEnv *env, jobject self, jobject params){
    printf("Hereeee\n");
    if (params == NULL) {
        return JNI_FALSE;
    }

    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        return JNI_FALSE;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        char *curve_name[] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1", "Curve25519"};
        for (int i = 0; i < 6; i++) {
            if (strcasecmp(utf_name, curve_name[i]) == 0) {
                (*env)->ReleaseStringUTFChars(env, name, utf_name);
                return JNI_TRUE;
            }
         }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        return JNI_FALSE;
    } else {
        return JNI_FALSE;
    }
    return JNI_FALSE;
    
}

static jobject create_ec_param_spec(JNIEnv *env) {
    return NULL;
}
/*
static jobject create_ec_param_spec(JNIEnv *env, const EC_GROUP *curve) {
    int field_type = EC_METHOD_get_field_type(EC_GROUP_method_of(curve));
    BIGNUM *a;
    BIGNUM *b;

    BIGNUM *gx;
    BIGNUM *gy;
    jobject field;

    if (field_type == NID_X9_62_prime_field) {
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

    } else if (field_type == NID_X9_62_characteristic_two_field) {
        a = BN_new();
        b = BN_new();
        if (!EC_GROUP_get_curve_GF2m(curve, NULL, a, b, NULL)) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating ECParameterSpec, EC_GROUP_get_curve_GF2m.");
            BN_free(a); BN_free(b);
            return NULL;
        }

        int basis_type = EC_GROUP_get_basis_type(curve);
        jintArray ks;
        jint *ks_data;
        if (basis_type == NID_X9_62_tpBasis) {
            ks = (*env)->NewIntArray(env, 1);
            ks_data = (*env)->GetIntArrayElements(env, ks, NULL);
            if (!EC_GROUP_get_trinomial_basis(curve, (unsigned int *) &ks_data[0])) {
                throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating ECParameterSpec, EC_GROUP_get_trinomial_basis.");
                BN_free(a); BN_free(b);
                (*env)->ReleaseIntArrayElements(env, ks, ks_data, JNI_ABORT);
                return NULL;
            }
        } else if (basis_type == NID_X9_62_ppBasis) {
            ks = (*env)->NewIntArray(env, 3);
            ks_data = (*env)->GetIntArrayElements(env, ks, NULL);
            if (!EC_GROUP_get_pentanomial_basis(curve, (unsigned int *) &ks_data[0], (unsigned int *) &ks_data[1], (unsigned int *) &ks_data[2])) {
                throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating ECParameterSpec, EC_GROUP_get_pentanomial_basis.");
                BN_free(a); BN_free(b);
                (*env)->ReleaseIntArrayElements(env, ks, ks_data, JNI_ABORT);
                return NULL;
            }
        } else {
            return NULL;
        }
        (*env)->ReleaseIntArrayElements(env, ks, ks_data, 0);

        jint m = EC_GROUP_get_degree(curve);

        jmethodID f2m_field_init = (*env)->GetMethodID(env, f2m_field_class, "<init>", "(I[I)V");
        field = (*env)->NewObject(env, f2m_field_class, f2m_field_init, m, ks);

        gx = BN_new();
        gy = BN_new();
        if (!EC_POINT_get_affine_coordinates_GF2m(curve, EC_GROUP_get0_generator(curve), gx, gy, NULL)) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Error creating ECParameterSpec, EC_POINT_get_affine_coordinates_GF2m.");
            BN_free(a); BN_free(b); BN_free(gx); BN_free(gy);
            return NULL;
        }
    } else {
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
    jint cofactor = BN_get_word(EC_GROUP_get0_cofactor(curve));

    jmethodID ec_parameter_spec_init = (*env)->GetMethodID(env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    return (*env)->NewObject(env, ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, order, cofactor);
}
*/
static jobject generate_from_curve(JNIEnv *env, const struct ecc_curve* curve) {
    printf("Hereeee I am\n");
    struct ecc_point pub;
    struct ecc_scalar priv;
    struct yarrow256_ctx yarrow;
    printf("Variables\n");
    yarrow256_init(&yarrow, 0, NULL);
    uint8_t  file = open("/dev/urandom", O_RDONLY);
    yarrow256_seed(&yarrow, YARROW256_SEED_FILE_SIZE, &file);
    close(file);
    printf("Generator\n");

    ecc_point_init(&pub, curve);
    ecc_scalar_init(&priv, curve);
    printf("Prepared\n");
    native_timing_start();
    ecdsa_generate_keypair(&pub, &priv, (void *) &yarrow, (nettle_random_func *) yarrow256_random);
    native_timing_stop();
    printf("Generated\n");
/*
    if (!result) {
        throw_new(env, "java/security/GeneralSecurityException", "Error generating key, EC_KEY_generate_key.");
        ecc_point_clear(&pub);
        ecc_scalar_clear(&priv);
        return NULL;
    }
*/
    mpz_t private_value;
    mpz_init(private_value);
    ecc_scalar_get(&priv, private_value);
    size_t size;
    mpz_export(NULL, &size, 1, sizeof(unsigned char), 0, 0, private_value);
    jbyteArray priv_bytes = (*env)->NewByteArray(env, size);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
    mpz_export((unsigned char*) key_priv, &size, 1, sizeof(unsigned char), 0, 0, private_value);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);


    unsigned long key_len = 2*size + 1;
    jbyteArray pub_bytes = (*env)->NewByteArray(env, key_len);
    mpz_t pub_value_x;
    mpz_init(pub_value_x);
    mpz_t pub_value_y;
    mpz_init(pub_value_y);
    ecc_point_get(&pub, pub_value_x, pub_value_y);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
    key_pub[0] = 0x04;
    mpz_export((unsigned char*) key_pub + 1, &size, 1, sizeof(unsigned char), 0, 0, pub_value_x);
    mpz_export((unsigned char*) key_pub + 1 + size, &size, 1, sizeof(unsigned char), 0, 0, pub_value_y);
    (*env)->ReleaseByteArrayElements(env, pub_bytes, key_pub, 0);


    int ec_param_spec;
    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_pub_param_spec);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);


}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}



JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random) {
    printf("Starting to degenerate\n");
    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        printf("This\n");
        return NULL;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        const struct ecc_curve* curve;
        int rc;
        char *curve_name[] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1", "Curve25519"};
        for (int i = 0; i < 6; i++) {
            printf("%s", curve_name[i]);
            if (strcasecmp(utf_name, curve_name[i]) == 0) {
                 printf("found it????");
                //(*env)->ReleaseStringUTFChars(env, name, utf_name);
                printf("gimme those curves\n");
                 curve = create_curve(env, params, curve_name[i]);
                 break;
            }
         }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        if (!curve) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
            return NULL;
        }
        jobject result = generate_from_curve(env, curve);
        return result;
    } else {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return NULL;
    }
    return NULL;
}


JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Nettle_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Nettle_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Nettle_sign(JNIEnv *env, jobject self, jbyteArray data, jbyteArray privkey, jobject params) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Nettle_verify(JNIEnv *env, jobject self, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return 0;
}
