#include "native.h"
#include <stdio.h>
#include <string.h>
#define LTM_DESC
#include <tomcrypt.h>

static prng_state ltc_prng;
static jclass provider_class;
static jclass ec_parameter_spec_class;
static jclass ecgen_parameter_spec_class;
static jclass pubkey_class;
static jclass privkey_class;
static jclass keypair_class;
static jclass elliptic_curve_class;
static jclass fp_field_class;
static jclass f2m_field_class;
static jclass point_class;
static jclass biginteger_class;

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TomcryptLib_createProvider(JNIEnv *env, jobject this) {
    /* Create the custom provider. */
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$TomCrypt");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    jstring name =  (*env)->NewStringUTF(env, "libtomcrypt " SCRYPT);
    double version = strtod(SCRYPT, NULL);

    return (*env)->NewObject(env, provider_class, init, name, version, name);
}


JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024TomCrypt_setup(JNIEnv *env, jobject this) {
    /* Initialize libtommath as the math lib. */
    ltc_mp = ltm_desc;

    jmethodID provider_put = (*env)->GetMethodID(env, provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    jstring ec = (*env)->NewStringUTF(env, "KeyPairGenerator.EC");
    jstring ec_value = (*env)->NewStringUTF(env, "cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$TomCrypt");
    (*env)->CallObjectMethod(env, this, provider_put, ec, ec_value);

    jstring ecdh = (*env)->NewStringUTF(env, "KeyAgreement.ECDH");
    jstring ecdh_value = (*env)->NewStringUTF(env, "cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$TomCrypt");
    (*env)->CallObjectMethod(env, this, provider_put, ecdh, ecdh_value);

    jstring ecdsa = (*env)->NewStringUTF(env, "Signature.ECDSA");
    jstring ecdsa_value = (*env)->NewStringUTF(env, "cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$TomCrypt");
    (*env)->CallObjectMethod(env, this, provider_put, ecdsa, ecdsa_value);

    int err;
    /* register yarrow */
    if (register_prng(&yarrow_desc) == -1) {
        fprintf(stderr, "Error registering Yarrow\n");
        return;
    }
    /* setup the PRNG */
    if ((err = rng_make_prng(128, find_prng("yarrow"), &ltc_prng, NULL)) != CRYPT_OK) {
        fprintf(stderr, "Error setting up PRNG, %s\n", error_to_string(err));
    }

    jclass local_ec_parameter_spec_class = (*env)->FindClass(env, "java/security/spec/ECParameterSpec");
    ec_parameter_spec_class = (*env)->NewGlobalRef(env, local_ec_parameter_spec_class);

    jclass local_ecgen_parameter_spec_class = (*env)->FindClass(env, "java/security/spec/ECGenParameterSpec");
    ecgen_parameter_spec_class = (*env)->NewGlobalRef(env, local_ecgen_parameter_spec_class);

    jclass local_pubkey_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeECPublicKey$TomCrypt");
    pubkey_class = (*env)->NewGlobalRef(env, local_pubkey_class);

    jclass local_privkey_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeECPrivateKey$TomCrypt");
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
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TomcryptLib_getCurves(JNIEnv *env, jobject this) {
    jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);
    const ltc_ecc_set_type * curve = ltc_ecc_sets;
    while (curve->size != 0) {
        jstring curve_name = (*env)->NewStringUTF(env, curve->name);
        (*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
        curve++;
    }

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TomCrypt_keysizeSupported(JNIEnv *env, jobject this, jint keysize){
    const ltc_ecc_set_type * curve = ltc_ecc_sets;
    while (curve->size != 0) {
        if (curve->size * 8 == keysize) {
            return JNI_TRUE;
        }
        curve++;
    }

    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TomCrypt_paramsSupported(JNIEnv *env, jobject this, jobject params){
    if (params == NULL) {
        return JNI_FALSE;
    }

    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
        jobject curve = (*env)->CallObjectMethod(env, params, get_curve);

        jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
        jobject field = (*env)->CallObjectMethod(env, curve, get_field);

        if ((*env)->IsInstanceOf(env, field, fp_field_class)) {
            jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
            jobject p = (*env)->CallObjectMethod(env, field, get_p);

            jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
            jobject a = (*env)->CallObjectMethod(env, curve, get_a);

            jmethodID biginteger_valueof = (*env)->GetStaticMethodID(env, biginteger_class, "valueOf", "(J)Ljava/math/BigInteger;");
            jobject three = (*env)->CallStaticObjectMethod(env, biginteger_class, biginteger_valueof, (jlong)3);

            jmethodID biginteger_add = (*env)->GetMethodID(env, biginteger_class, "add", "(Ljava/math/BigInteger;)Ljava/math/BigInteger;");
            jobject a_3 = (*env)->CallObjectMethod(env, a, biginteger_add, three);

            jmethodID biginteger_equals = (*env)->GetMethodID(env, biginteger_class, "equals", "(Ljava/lang/Object;)Z");
            jboolean eq = (*env)->CallBooleanMethod(env, p, biginteger_equals, a_3);
            return eq;
        } else if ((*env)->IsInstanceOf(env, field, f2m_field_class)) {
            return JNI_FALSE;
        } else {
            return JNI_FALSE;
        }
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        const ltc_ecc_set_type * curve = ltc_ecc_sets;
        while (curve->size != 0) {
            if (strcasecmp(utf_name, curve->name) == 0) {
                (*env)->ReleaseStringUTFChars(env, name, utf_name);
                return JNI_TRUE;
            }
            curve++;
        }
        return JNI_FALSE;
    } else {
        return JNI_FALSE;
    }
}

static jobject create_ec_param_spec(JNIEnv *env, const ltc_ecc_set_type *curve) {
    jstring p_string = (*env)->NewStringUTF(env, curve->prime);
    jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(Ljava/lang/String;I)V");
    jobject p = (*env)->NewObject(env, biginteger_class, biginteger_init, p_string, (jint) 16);

    jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject field = (*env)->NewObject(env, fp_field_class, fp_field_init, p);

    jmethodID biginteger_subtract = (*env)->GetMethodID(env, biginteger_class, "subtract", "(Ljava/math/BigInteger;)Ljava/math/BigInteger;");
    jmethodID biginteger_valueof = (*env)->GetStaticMethodID(env, biginteger_class, "valueOf", "(J)Ljava/math/BigInteger;");
    jobject three = (*env)->CallStaticObjectMethod(env, biginteger_class, biginteger_valueof, (jlong) 3);
    jobject a = (*env)->CallObjectMethod(env, p, biginteger_subtract, three);

    jstring b_string = (*env)->NewStringUTF(env, curve->B);
    jobject b = (*env)->NewObject(env, biginteger_class, biginteger_init, b_string, (jint) 16);

    jmethodID elliptic_curve_init = (*env)->GetMethodID(env, elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = (*env)->NewObject(env, elliptic_curve_class, elliptic_curve_init, field, a, b);

    jstring gx_string = (*env)->NewStringUTF(env, curve->Gx);
    jstring gy_string = (*env)->NewStringUTF(env, curve->Gy);
    jobject gx = (*env)->NewObject(env, biginteger_class, biginteger_init, gx_string, (jint) 16);
    jobject gy = (*env)->NewObject(env, biginteger_class, biginteger_init, gy_string, (jint) 16);

    jmethodID point_init = (*env)->GetMethodID(env, point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject g = (*env)->NewObject(env, point_class, point_init, gx, gy);

    jstring n_string = (*env)->NewStringUTF(env, curve->order);
    jobject n = (*env)->NewObject(env, biginteger_class, biginteger_init, n_string, (jint) 16);

    jmethodID ec_parameter_spec_init = (*env)->GetMethodID(env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    return (*env)->NewObject(env, ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, n, (jint) 1);
}

static char *biginteger_to_hex(JNIEnv *env, jobject big, jint bytes) {
    jmethodID to_string = (*env)->GetMethodID(env, biginteger_class, "toString", "(I)Ljava/lang/String;");
    jstring big_string = (*env)->CallObjectMethod(env, big, to_string, (jint) 16);

    jsize len = (*env)->GetStringUTFLength(env, big_string);
    char raw_string[len];
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

static ltc_ecc_set_type* create_curve(JNIEnv *env, jobject params) {
    jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

    jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
    jint bits = (*env)->CallIntMethod(env, field, get_bits);
    jint bytes = (bits + (8 - bits % 8)) / 8;

    jmethodID get_b = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
    jobject b = (*env)->CallObjectMethod(env, elliptic_curve, get_b);

    jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
    jobject p = (*env)->CallObjectMethod(env, field, get_p);

    jmethodID get_g = (*env)->GetMethodID(env, ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
    jobject g = (*env)->CallObjectMethod(env, params, get_g);

    jmethodID get_x = (*env)->GetMethodID(env, point_class, "getAffineX", "()Ljava/math/BigInteger;");
    jobject gx = (*env)->CallObjectMethod(env, g, get_x);

    jmethodID get_y = (*env)->GetMethodID(env, point_class, "getAffineY", "()Ljava/math/BigInteger;");
    jobject gy = (*env)->CallObjectMethod(env, g, get_y);

    jmethodID get_n = (*env)->GetMethodID(env, ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
    jobject n = (*env)->CallObjectMethod(env, params, get_n);

    ltc_ecc_set_type *curve = calloc(sizeof(ltc_ecc_set_type), 1);
    curve->size = bytes;
    curve->name = "";
    curve->prime = biginteger_to_hex(env, p, bytes);
    curve->B = biginteger_to_hex(env, b, bytes);
    curve->order = biginteger_to_hex(env, n, bytes);
    curve->Gx = biginteger_to_hex(env, gx, bytes);
    curve->Gy = biginteger_to_hex(env, gy, bytes);

    return curve;
}

static jobject generate_from_curve(JNIEnv *env, const ltc_ecc_set_type *curve) {
    ecc_key key;
    int err;
    if ((err = ecc_make_key_ex(&ltc_prng, find_prng("yarrow"), &key, curve)) != CRYPT_OK) {
        printf("Error making key: %s\n", error_to_string(err));
        return NULL;
    }
    unsigned long key_len = 2*curve->size + 1;
    jbyteArray pub_bytes = (*env)->NewByteArray(env, key_len);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
    ecc_ansi_x963_export(&key, key_pub, &key_len);
    (*env)->ReleaseByteArrayElements(env, pub_bytes, key_pub, 0);

    jobject ec_param_spec = create_ec_param_spec(env, curve);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_param_spec);

    jbyteArray priv_bytes = (*env)->NewByteArray(env, curve->size);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
    mp_to_unsigned_bin(key.k, key_priv);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

    ecc_free(&key);
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TomCrypt_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject this, jint keysize, jobject random){
    int key_bytes = keysize / 8;

    const ltc_ecc_set_type *curve = ltc_ecc_sets;
    while (curve->size != 0) {
        if (curve->size == key_bytes) {
            break;
        }
        curve++;
    }

    if (curve->size == 0) {
        return NULL;
    }

    return generate_from_curve(env, curve);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TomCrypt_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject this, jobject params, jobject random){
    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        ltc_ecc_set_type *curve = create_curve(env, params);
        jobject result = generate_from_curve(env, curve);
        free(curve);
        return result;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        const ltc_ecc_set_type* curve = ltc_ecc_sets;
        while (curve->size != 0) {
            if (strcasecmp(utf_name, curve->name) == 0) {
                break;
            }
            curve++;
        }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);

        return generate_from_curve(env, curve);
    } else {
        return NULL;
    }
}