#include "native.h"
#include <stdio.h>
#include <string.h>
#include <tomcrypt.h>
#include "c_utils.h"
#include "c_timing.h"

static prng_state ltc_prng;
static jclass provider_class;

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

    jstring ecdsa = (*env)->NewStringUTF(env, "Signature.NONEwithECDSA");
    jstring ecdsa_value = (*env)->NewStringUTF(env, "cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$TomCryptRaw");
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

    init_classes(env, "TomCrypt");
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
    int key_bytes = (keysize + 7) / 8;
    const ltc_ecc_set_type * curve = ltc_ecc_sets;
    while (curve->size != 0) {
        if (curve->size == key_bytes) {
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
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
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

static ltc_ecc_set_type* create_curve(JNIEnv *env, jobject params) {
    jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

    jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
    jint bits = (*env)->CallIntMethod(env, field, get_bits);
    jint bytes = (bits + 7) / 8;

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
	jmethodID get_bitlength = (*env)->GetMethodID(env, biginteger_class, "bitLength", "()I");
	jint ord_bits = (*env)->CallIntMethod(env, n, get_bitlength);
	jint ord_bytes = (ord_bits + 7) / 8; 

    ltc_ecc_set_type *curve = calloc(sizeof(ltc_ecc_set_type), 1);
    curve->size = bytes;
    curve->name = "";
    curve->prime = biginteger_to_hex(env, p, bytes);
    curve->B = biginteger_to_hex(env, b, bytes);
    curve->order = biginteger_to_hex(env, n, ord_bytes);
    curve->Gx = biginteger_to_hex(env, gx, bytes);
    curve->Gy = biginteger_to_hex(env, gy, bytes);

    return curve;
}

static void free_curve(ltc_ecc_set_type *curve) {
    if (curve) {
        free((void*)curve->prime);
        free((void*)curve->B);
        free((void*)curve->order);
        free((void*)curve->Gx);
        free((void*)curve->Gy);
        free(curve);
    }
}

static jobject generate_from_curve(JNIEnv *env, const ltc_ecc_set_type *curve) {
    ecc_key key;

    native_timing_start();
    int err = ecc_make_key_ex(&ltc_prng, find_prng("yarrow"), &key, curve);
    native_timing_stop();

    if (err != CRYPT_OK) {
        throw_new(env, "java/security/GeneralSecurityException", error_to_string(err));
        return NULL;
    }
    unsigned long key_len = 2*curve->size + 1;
    jbyteArray pub_bytes = (*env)->NewByteArray(env, key_len);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
    ecc_ansi_x963_export(&key, (unsigned char *) key_pub, &key_len);
    (*env)->ReleaseByteArrayElements(env, pub_bytes, key_pub, 0);

    jobject ec_param_spec = create_ec_param_spec(env, curve);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_pub_param_spec);

    jbyteArray priv_bytes = (*env)->NewByteArray(env, curve->size);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
    ltc_mp.unsigned_write(key.k, (unsigned char *) key_priv);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

    ecc_free(&key);
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TomCrypt_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject this, jint keysize, jobject random){
    int key_bytes = (keysize + 7) / 8;

    const ltc_ecc_set_type *curve = ltc_ecc_sets;
    while (curve->size != 0) {
        if (curve->size == key_bytes) {
            break;
        }
        curve++;
    }

    if (curve->size == 0) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
        return NULL;
    }

    return generate_from_curve(env, curve);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TomCrypt_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject this, jobject params, jobject random){
    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        ltc_ecc_set_type *curve = create_curve(env, params);
        jobject result = generate_from_curve(env, curve);
        free_curve(curve);
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
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return NULL;
    }
}

static jboolean privkey_from_bytes(JNIEnv *env, jbyteArray privkey, const ltc_ecc_set_type *curve, ecc_key *out) {
    jsize priv_size = (*env)->GetArrayLength(env, privkey);
    jbyte *priv_data = (*env)->GetByteArrayElements(env, privkey, NULL);

    if (curve->size != priv_size) {
        throw_new(env, "java/lang/IllegalStateException", "Curve size does not match the private key size.");
        (*env)->ReleaseByteArrayElements(env, privkey, priv_data, JNI_ABORT);
        return JNI_FALSE;
    }

    out->type = PK_PRIVATE;
    out->idx = -1;
    out->dp = curve;
    ltc_mp.init(&out->k);
    ltc_mp.unsigned_read(out->k, (unsigned char *) priv_data, (unsigned long) curve->size);

    (*env)->ReleaseByteArrayElements(env, privkey, priv_data, JNI_ABORT);
    return JNI_TRUE;
}

static jboolean pubkey_from_bytes(JNIEnv *env, jbyteArray pubkey, const ltc_ecc_set_type *curve, ecc_key *out) {
    jsize pub_size = (*env)->GetArrayLength(env, pubkey);
    jbyte *pub_data = (*env)->GetByteArrayElements(env, pubkey, NULL);

    if (curve->size != (pub_size - 1) / 2) {
        throw_new(env, "java/lang/IllegalStateException", "Curve size does not match the public key size.");
        (*env)->ReleaseByteArrayElements(env, pubkey, pub_data, JNI_ABORT);
        return JNI_FALSE;
    }

    out->type = PK_PUBLIC;
    out->idx = -1;
    out->dp = curve;
    ltc_init_multi(&out->pubkey.x, &out->pubkey.y, &out->pubkey.z, NULL);
    ltc_mp.set_int(out->pubkey.z, 1);
    ltc_mp.unsigned_read(out->pubkey.x, (unsigned char *) pub_data + 1, (unsigned long) curve->size);
    ltc_mp.unsigned_read(out->pubkey.y, (unsigned char *) pub_data + 1 + curve->size, (unsigned long) curve->size);

    (*env)->ReleaseByteArrayElements(env, pubkey, pub_data, JNI_ABORT);

    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024TomCrypt_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params){
    ltc_ecc_set_type *curve = create_curve(env, params);

    ecc_key pub;
    if (!pubkey_from_bytes(env, pubkey, curve, &pub)) {
        free_curve(curve);
        return NULL;
    }

    ecc_key priv;
    if (!privkey_from_bytes(env, privkey, curve, &priv)) {
        free_curve(curve);
        return NULL;
    }

    unsigned char result[curve->size];
    unsigned long output_len = curve->size;

    native_timing_start();
    int err = ecc_shared_secret(&priv, &pub, result, &output_len);
    native_timing_stop();

    if (err != CRYPT_OK) {
        throw_new(env, "java/security/GeneralSecurityException", error_to_string(err));
        free_curve(curve);
        return NULL;
    }

    jbyteArray output = (*env)->NewByteArray(env, curve->size);
    jbyte *output_data = (*env)->GetByteArrayElements(env, output, NULL);
    memcpy(output_data, result, curve->size);
    (*env)->ReleaseByteArrayElements(env, output, output_data, 0);

    ltc_cleanup_multi(&pub.pubkey.x, &pub.pubkey.y, &pub.pubkey.z, &priv.k, NULL);
    free_curve(curve);
    return output;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024TomCrypt_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024TomCryptRaw_sign(JNIEnv *env, jobject this, jbyteArray data, jbyteArray privkey, jobject params) {
    ltc_ecc_set_type *curve = create_curve(env, params);

    ecc_key priv;
    if (!privkey_from_bytes(env, privkey, curve, &priv)) {
        free_curve(curve);
        return NULL;
    }

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);

    unsigned char result[curve->size*4];
    unsigned long output_len = curve->size*4;

    native_timing_start();
    int err = ecc_sign_hash((unsigned char *) data_data, data_size, result, &output_len, &ltc_prng, find_prng("yarrow"), &priv);
    native_timing_stop();

    if (err != CRYPT_OK) {
        throw_new(env, "java/security/GeneralSecurityException", error_to_string(err));
        free_curve(curve);
        (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
        return NULL;
    }

    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);

    jbyteArray output = (*env)->NewByteArray(env, output_len);
    jbyte *output_data = (*env)->GetByteArrayElements(env, output, NULL);
    memcpy(output_data, result, output_len);
    (*env)->ReleaseByteArrayElements(env, output, output_data, 0);

    free_curve(curve);
    return output;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024TomCryptRaw_verify(JNIEnv *env, jobject this, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
    ltc_ecc_set_type *curve = create_curve(env, params);

    ecc_key pub;
    if (!pubkey_from_bytes(env, pubkey, curve, &pub)) {
        free_curve(curve);
        return JNI_FALSE;
    }

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);

    jsize sig_size = (*env)->GetArrayLength(env, signature);
    jbyte *sig_data = (*env)->GetByteArrayElements(env, signature, NULL);

    int result;
    native_timing_start();
    int err = ecc_verify_hash((unsigned char *) sig_data, sig_size, (unsigned char *) data_data, data_size, &result, &pub);
    native_timing_stop();

    if (err != CRYPT_OK) {
        throw_new(env, "java/security/GeneralSecurityException", error_to_string(err));
        free_curve(curve);
        (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, signature, sig_data, JNI_ABORT);
        return JNI_FALSE;
    }

    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_data, JNI_ABORT);
    free_curve(curve);
    return result;
}