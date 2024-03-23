#include "native.h"
#include <string.h>

#include <nettle/version.h>
#include <nettle/ecc.h>
#include <nettle/ecc-curve.h>
#include <nettle/ecdsa.h>
#include <nettle/yarrow.h>
#include <nettle/dsa.h>
#include <gmp.h>
#include <fcntl.h>
#include <unistd.h>

#include "c_utils.h"
#include "c_timing.h"

static struct yarrow256_ctx yarrow;


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
    ADD_KA(env, self, "ECDH", "NettleECDH");
    ADD_SIG(env, self, "NONEwithECDSA", "NettleECDSAwithNONE");

    init_classes(env, "Nettle");

    yarrow256_init(&yarrow, 0, NULL);
    uint8_t  file = open("/dev/random", O_RDONLY);
    yarrow256_seed(&yarrow, YARROW256_SEED_FILE_SIZE, &file);
    close(file);

}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_NettleLib_getCurves(JNIEnv *env, jobject self) {
    jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);
    char *curve_names[] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};
    for (int i = 0; i < 5; i++) {
        jstring curve_name = (*env)->NewStringUTF(env, curve_names[i]);
        (*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
    }
    
    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_keysizeSupported(JNIEnv *env, jobject self, jint keysize) {
    int supported[] = {192, 224, 256, 384, 521};
    for (int i = 0; i < 5; i++) {
        if (keysize == supported[i]) {
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

static const struct ecc_curve* create_curve(JNIEnv *env, const char* curve_name) {
    const struct ecc_curve* curve = NULL;
    if (curve_name) {
        if (strcasecmp("secp192r1", curve_name) == 0) {
            curve = nettle_get_secp_192r1();
        }
        if (strcasecmp("secp224r1", curve_name) == 0) {
            curve = nettle_get_secp_224r1();
        }
        if (strcasecmp("secp256r1", curve_name) == 0) {
            curve = nettle_get_secp_256r1();
        }
        if (strcasecmp("secp384r1", curve_name) == 0) {
            curve = nettle_get_secp_384r1();
        }
        if (strcasecmp("secp521r1", curve_name) == 0) {
            curve = nettle_get_secp_521r1();
        }
        return curve;
    }
    return NULL;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_paramsSupported(JNIEnv *env, jobject self, jobject params){
    if (params == NULL) {
        return JNI_FALSE;
    }

    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        return JNI_FALSE;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);

        char *curve_name[5] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};
        for (int i = 0; i < sizeof(curve_name); i++) {
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

static jobject generate_from_curve(JNIEnv *env, const struct ecc_curve* curve, jobject spec, int byte_size) {

    struct ecc_point pub;
    struct ecc_scalar priv;

    ecc_point_init(&pub, curve);
    ecc_scalar_init(&priv, curve);
    native_timing_start();
    ecdsa_generate_keypair(&pub, &priv, (void *) &yarrow, (nettle_random_func *) yarrow256_random);
    native_timing_stop();

    mpz_t private_value;
    mpz_init(private_value);
    ecc_scalar_get(&priv, private_value);
    size_t size = 0;
    size_t xLen = 0;
    size_t yLen = 0;
    mpz_export(NULL, &size, 1, sizeof(unsigned char), 0, 0, private_value);
    jbyteArray priv_bytes = (*env)->NewByteArray(env, byte_size);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);

    int diff = byte_size - size;
    memset(key_priv, 0x00, diff);

    mpz_export((unsigned char*) key_priv + diff, &size, 1, sizeof(unsigned char), 0, 0, private_value);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);


    unsigned long key_len = 2*byte_size + 1;
    jbyteArray pub_bytes = (*env)->NewByteArray(env, key_len);
    mpz_t pub_value_x;
    mpz_init(pub_value_x);
    mpz_t pub_value_y;
    mpz_init(pub_value_y);
    ecc_point_get(&pub, pub_value_x, pub_value_y);
    jbyte *key_pub = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
    key_pub[0] = 0x04;

    mpz_export(NULL, &xLen, 1, sizeof(unsigned char), 0, 0, pub_value_x);
    diff = byte_size - xLen;
    memset(key_pub + 1, 0x00, diff);
    mpz_export((unsigned char*) key_pub + 1+diff, &xLen, 1, sizeof(unsigned char), 0, 0, pub_value_x);

    mpz_export(NULL, &yLen, 1, sizeof(unsigned char), 0, 0, pub_value_y);
    diff = byte_size - yLen;
    memset(key_pub + 1 + byte_size, 0x00, diff);
    mpz_export((unsigned char*) key_pub + 1 + byte_size + diff, &yLen, 1, sizeof(unsigned char), 0, 0, pub_value_y);
    (*env)->ReleaseByteArrayElements(env, pub_bytes, key_pub, 0);


    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_pub_param_spec);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    mpz_clears(private_value, pub_value_x, pub_value_y, NULL);
    ecc_point_clear(&pub);
    ecc_scalar_clear(&priv);
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);


}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}



JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Nettle_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2Ljava_security_spec_AlgorithmParameterSpec_2(JNIEnv *env, jobject self, jobject params, jobject random, jobject spec) {

    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        return NULL;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
        jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        const struct ecc_curve* curve;
        int byte_size;
        char *curve_name[5] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};
        int byte_sizes[] = {24, 28, 32, 48, 66};
        for (int i = 0; i < sizeof(curve_name); i++) {
            if (strcasecmp(utf_name, curve_name[i]) == 0) {
                 curve = create_curve(env, curve_name[i]);
                 byte_size = byte_sizes[i];
                 break;
            }
         }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        if (!curve) {
            throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
            return NULL;
        }
        jobject result = generate_from_curve(env, curve, spec, byte_size);
        return result;
    } else {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
        return NULL;
    }
    return NULL;
}

int barray_to_pubkey(JNIEnv *env, struct ecc_point* pubKey , jbyteArray pub) {
    jsize pub_len = (*env)->GetArrayLength(env, pub);
    jbyte *pub_data = (*env)->GetByteArrayElements(env, pub, NULL);
    int pointLength = (pub_len - 1) / 2;
    mpz_t x;
    mpz_t y;
    mpz_init(x);
    mpz_init(y);
    mpz_import(x, pointLength, 1, sizeof(unsigned char), 0, 0, pub_data+1);
    mpz_import(y, pointLength, 1, sizeof(unsigned char), 0, 0, pub_data+1+pointLength);
    (*env)->ReleaseByteArrayElements(env, pub, pub_data, JNI_ABORT);
    ecc_point_set(pubKey, x, y);
    return pointLength;
}

int barray_to_privkey(JNIEnv *env, struct ecc_scalar* privKey, jbyteArray priv) {
    jsize priv_len = (*env)->GetArrayLength(env, priv);
    jbyte *priv_data = (*env)->GetByteArrayElements(env, priv, NULL);
    mpz_t mp;
    mpz_init(mp);
    mpz_import(mp, priv_len, 1, sizeof(unsigned char), 0, 0, priv_data);
    (*env)->ReleaseByteArrayElements(env, priv, priv_data, JNI_ABORT);
    ecc_scalar_set(privKey, mp);
    return priv_len;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Nettle_generateSecret___3B_3BLjava_security_spec_ECGenParameterSpec_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params) {
    jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
    jstring name = (*env)->CallObjectMethod(env, params, get_name);
    const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
    const struct ecc_curve* curve;
    char *curve_name[5] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};
    int byte_sizes[] = {24, 28, 32, 48, 66};
    int byte_size;
    for (int i = 0; i < sizeof(curve_name); i++) {
        if (strcasecmp(utf_name, curve_name[i]) == 0) {
             curve = create_curve(env, curve_name[i]);
             byte_size = byte_sizes[i];
             break;
        }
    }
    (*env)->ReleaseStringUTFChars(env, name, utf_name);
    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
        return NULL;
    }

    struct ecc_scalar privScalar;
    ecc_scalar_init(&privScalar, curve);
    barray_to_privkey(env, &privScalar, privkey);

    struct ecc_point eccPubPoint;
    ecc_point_init(&eccPubPoint, curve);
    barray_to_pubkey(env, &eccPubPoint, pubkey);

    struct ecc_point resultPoint;
    ecc_point_init(&resultPoint, curve);

    jbyteArray result = (*env)->NewByteArray(env, byte_size);
    jbyte *result_data = (*env)->GetByteArrayElements(env, result, NULL);

    native_timing_start();
    ecc_point_mul(&resultPoint, &privScalar, &eccPubPoint);
    native_timing_stop();

    mpz_t x;
    mpz_init(x);
    ecc_point_get(&resultPoint, x, NULL);

    size_t size;

    mpz_export(NULL, &size, 1, sizeof(unsigned char), 0, 0, x);
    int diff = byte_size - size;
    memset(result_data, 0x00, diff);
    mpz_export((unsigned char*) result_data + diff, &size, 1, sizeof(unsigned char), 0, 0, x);
    (*env)->ReleaseByteArrayElements(env, result, result_data, 0);
    ecc_scalar_clear(&privScalar);
    ecc_point_clear(&eccPubPoint);
    ecc_point_clear(&resultPoint);
    mpz_clear(x);
    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Nettle_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

// credit to https://github.com/crocs-muni/ECTester/blob/master/src/cz/crcs/ectester/standalone/libs/jni/c_utils.c
size_t signature_to_der(struct dsa_signature* signature, unsigned char *result, int byte_size) {
    size_t r_tmpSize;
    size_t s_tmpSize;
    size_t sequenceSize;
    size_t sequenceSizeSize = 0;
    size_t wholeSize;

    mpz_export(NULL, &r_tmpSize, 1, sizeof(unsigned char), 0, 0, signature->r);
    mpz_export(NULL, &s_tmpSize, 1, sizeof(unsigned char), 0, 0, signature->s);

    unsigned char r_tmp[r_tmpSize];
    unsigned char s_tmp[s_tmpSize];
    mpz_export(r_tmp, &r_tmpSize, 1, sizeof(unsigned char), 0, 0, signature->r);
    mpz_export(s_tmp, &s_tmpSize, 1, sizeof(unsigned char), 0, 0, signature->s);

    size_t rSize = r_tmpSize + (r_tmp[0] & 0x80 ? 1 : 0);
    size_t sSize = s_tmpSize + (s_tmp[0] & 0x80 ? 1 : 0);

    sequenceSize = 2 + rSize + 2 + sSize;

    if (sequenceSize > 127) {
        size_t s = sequenceSize;
        do {
            sequenceSizeSize++;
        } while ((s = s >> 8));
    }

    wholeSize = sequenceSize + sequenceSizeSize + 2;
    if (!result) {
        return wholeSize;
    }

    int index = 0;
    result[index++] = 0x30;
    if (sequenceSize < 128) {
        result[index++] = sequenceSize;
    } else {
        result[index++] = sequenceSizeSize | 0x80;
        for (size_t i = 0; i < sequenceSizeSize; i++) {
            result[index++] = sequenceSize & (0xff << (8 * (sequenceSizeSize - i - 1)));
        }
    }
    result[index++] = 0x02;
    result[index++] = rSize;
    if (r_tmp[0] & 0x80) {
        result[index++] = 0x00;
    }
    memcpy(result + index, r_tmp, r_tmpSize);
    index += r_tmpSize;
    result[index++] = 0x02;
    result[index++] = sSize;
    if (s_tmp[0] & 0x80) {
        result[index++] = 0x00;
    }
    memcpy(result + index, s_tmp, s_tmpSize);
    return wholeSize;
}

// credit to https://github.com/crocs-muni/ECTester/blob/master/src/cz/crcs/ectester/standalone/libs/jni/c_utils.cs
int der_to_signature(struct dsa_signature* signature, unsigned char* der) {
    int index = 0;
    size_t sequenceSize;
    size_t sequenceSizeSize;
    if (der[index++] != 0x30) {
        return 0;
    }

    if (!(der[index] & 0x80)) {
        sequenceSize = der[index++];
    } else {
        sequenceSizeSize = der[index++] & 0x7f;
        while(sequenceSizeSize > 0) {
       	    sequenceSizeSize--;
            sequenceSize |= der[index++] << (sequenceSizeSize);
        }
    }

    if (der[index++] != 0x02) {
        return 0;
    }

    size_t rLength = der[index++];
    mpz_import(signature->r, rLength, 1, sizeof(unsigned char), 0, 0, der + index);
	index += rLength;
    if (der[index++] != 0x02) {
        return 0;
    }
    size_t sLength = der[index++];
    mpz_import(signature->s, sLength, 1, sizeof(unsigned char), 0, 0, der + index);
    return 1;

}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Nettle_sign(JNIEnv *env, jobject self, jbyteArray data, jbyteArray privkey, jobject params) {
    jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
    jstring name = (*env)->CallObjectMethod(env, params, get_name);
    const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
    const struct ecc_curve* curve;
    int byte_size;
    char *curve_name[5] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};
    int byte_sizes[] = {24, 28, 32, 48, 66};
    for (int i = 0; i < sizeof(curve_name); i++) {
        if (strcasecmp(utf_name, curve_name[i]) == 0) {
             curve = create_curve(env, curve_name[i]);
             byte_size = byte_sizes[i] + 1;
             break;
        }
    }
    (*env)->ReleaseStringUTFChars(env, name, utf_name);
    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
        return NULL;
    }
    struct ecc_scalar privScalar;
    ecc_scalar_init(&privScalar, curve);
    barray_to_privkey(env, &privScalar, privkey);

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);

    struct dsa_signature signature;
    dsa_signature_init(&signature);

    native_timing_start();
    ecdsa_sign(&privScalar, (void *) &yarrow, (nettle_random_func *) yarrow256_random, data_size, (unsigned char*)data_data, &signature);
    native_timing_stop();

    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);


    jsize sig_len = signature_to_der(&signature, NULL, byte_size);
    jbyteArray result = (*env)->NewByteArray(env, sig_len);
    jbyte *result_data = (*env)->GetByteArrayElements(env, result, NULL);
    signature_to_der(&signature, (unsigned char *)result_data, byte_size);
    (*env)->ReleaseByteArrayElements(env, result, result_data, 0);

    ecc_scalar_clear(&privScalar);
    dsa_signature_clear(&signature);
    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Nettle_verify(JNIEnv *env, jobject self, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
    jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
    jstring name = (*env)->CallObjectMethod(env, params, get_name);
    const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
    const struct ecc_curve* curve;
    char *curve_name[5] = {"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};
    for (int i = 0; i < sizeof(curve_name); i++) {
        if (strcasecmp(utf_name, curve_name[i]) == 0) {
             curve = create_curve(env, curve_name[i]);
             break;
        }
    }
    (*env)->ReleaseStringUTFChars(env, name, utf_name);
    if (!curve) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve for given bitsize not found.");
        return false;
    }

    struct ecc_point eccPubPoint;
    ecc_point_init(&eccPubPoint, curve);
    barray_to_pubkey(env, &eccPubPoint, pubkey);

    jbyte *sig_data = (*env)->GetByteArrayElements(env, signature, NULL);

    struct dsa_signature eccSignature;
    dsa_signature_init(&eccSignature);

    if (!der_to_signature(&eccSignature, (unsigned char*) sig_data)) {
        throw_new(env, "java/security/InvalidAlgorithmParameterException", "Invalid DER encoding of the signature.");
        return false;
    }

    (*env)->ReleaseByteArrayElements(env, signature, sig_data, JNI_ABORT);

    jsize data_size = (*env)->GetArrayLength(env, data);
    jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);

    native_timing_start();
    int result = ecdsa_verify(&eccPubPoint, data_size, (unsigned char*)data_data, &eccSignature);
    native_timing_stop();
    (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);

    ecc_point_clear(&eccPubPoint);
    dsa_signature_clear(&eccSignature);
    return (result == 1) ? JNI_TRUE : JNI_FALSE;
}
