#include "native.h"
#include <string.h>
#include <stdio.h>

#include <cryptoApi.h>
#include <coreApi.h>

#include "c_utils.h"
#include "c_timing.h"

static jclass provider_class;


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MatrixsslLib_createProvider(JNIEnv *env, jobject this) {
    /* Create the custom provider. */
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Matrixssl");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    jstring name =  (*env)->NewStringUTF(env, "MatrixSSL");
    double version = 4.1;

    return (*env)->NewObject(env, provider_class, init, name, version, name);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Matrixssl_setup(JNIEnv *env, jobject this) {
	INIT_PROVIDER(env, provider_class);

	ADD_KPG(env, this, "EC", "Matrixssl");
	ADD_KA(env, this, "ECDH", "MatrixsslECDH");
	ADD_SIG(env, this, "NONEwithECDSA", "MatrixsslECDSAwithNONE");

	psCoreOpen(PSCORE_CONFIG);
	psOpenPrng();

	init_classes(env, "Matrixssl");
}


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MatrixsslLib_getCurves(JNIEnv *env, jobject this) {
	jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);
	size_t i = 0;
	while (eccCurves[i].size > 0) {
		jstring curve_name = (*env)->NewStringUTF(env, eccCurves[i].name);
		(*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
		i++;
	}
	return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Matrixssl_keysizeSupported(JNIEnv *env, jobject this, jint keysize) {
	size_t i = 0;
	while (eccCurves[i].size > 0) {
		if (eccCurves[i].size * 8 == keysize) {
			return JNI_TRUE;
		}
		i++;
	}
	return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Matrixssl_paramsSupported(JNIEnv *env, jobject this, jobject params) {
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
		size_t i = 0;
		while (eccCurves[i].size > 0) {
            if (strcasecmp(utf_name, eccCurves[i].name) == 0) {
                (*env)->ReleaseStringUTFChars(env, name, utf_name);
                return JNI_TRUE;
            }
			i++;
        }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        return JNI_FALSE;
    } else {
        return JNI_FALSE;
    }
}


static jobject create_ec_param_spec(JNIEnv *env, const psEccCurve_t *curve) {
	jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(Ljava/lang/String;I)V");
	
	jstring p_string = (*env)->NewStringUTF(env, curve->prime);
	jobject p = (*env)->NewObject(env, biginteger_class, biginteger_init, p_string, (jint) 16);

	jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject field = (*env)->NewObject(env, fp_field_class, fp_field_init, p);

	jstring a_string = (*env)->NewStringUTF(env, curve->A);
    jobject a = (*env)->NewObject(env, biginteger_class, biginteger_init, a_string, (jint) 16);
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

static psEccCurve_t *create_curve(JNIEnv *env, jobject params) {
	psEccCurve_t *curve = calloc(sizeof(psEccCurve_t), 1);

	jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

    jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
    jint bits = (*env)->CallIntMethod(env, field, get_bits);
    jint bytes = (bits + 7) / 8;
	curve->size = bytes;

	jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
    jobject p = (*env)->CallObjectMethod(env, field, get_p);

	jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
    jobject a = (*env)->CallObjectMethod(env, elliptic_curve, get_a);

	jmethodID get_b = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
    jobject b = (*env)->CallObjectMethod(env, elliptic_curve, get_b);

    jmethodID get_g = (*env)->GetMethodID(env, ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
    jobject g = (*env)->CallObjectMethod(env, params, get_g);

    jmethodID get_x = (*env)->GetMethodID(env, point_class, "getAffineX", "()Ljava/math/BigInteger;");
    jobject gx = (*env)->CallObjectMethod(env, g, get_x);

    jmethodID get_y = (*env)->GetMethodID(env, point_class, "getAffineY", "()Ljava/math/BigInteger;");
    jobject gy = (*env)->CallObjectMethod(env, g, get_y);

    jmethodID get_n = (*env)->GetMethodID(env, ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
    jobject n = (*env)->CallObjectMethod(env, params, get_n);

	//jmethodID get_h = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCofactor", "()I");
	//jint h = (*env)->CallIntMethod(env, params, get_h);

	jmethodID get_bitlength = (*env)->GetMethodID(env, biginteger_class, "bitLength", "()I");
	jint ord_bits = (*env)->CallIntMethod(env, n, get_bitlength);
	jint ord_bytes = (ord_bits + 7) / 8;

	curve->prime = biginteger_to_hex(env, p, bytes);
	curve->A = biginteger_to_hex(env, a, bytes);
	curve->B = biginteger_to_hex(env, b, bytes);
	curve->Gx = biginteger_to_hex(env, gx, bytes);
	curve->Gy = biginteger_to_hex(env, gy, bytes);
	curve->order = biginteger_to_hex(env, n, ord_bytes);
	return curve;
}

static void free_curve(psEccCurve_t *curve) {
	free((char *)curve->prime);
	free((char *)curve->A);
	free((char *)curve->B);
	free((char *)curve->order);
	free((char *)curve->Gx);
	free((char *)curve->Gy);
}

static jobject generate_from_curve(JNIEnv *env, const psEccCurve_t *curve) {
	psEccKey_t *key;
	int32_t err = psEccNewKey(NULL, &key, curve);
	err = psEccInitKey(NULL, key, curve);

	native_timing_start();
	err = psEccGenKey(NULL, key, curve, NULL);
	native_timing_stop();

	if (err < 0) {
		throw_new(env, "java/security/GeneralSecurityException", "Couldn't generate key.");
		psEccClearKey(key);
		psEccDeleteKey(&key);
		return NULL;
	}

	jbyteArray priv = (*env)->NewByteArray(env, pstm_unsigned_bin_size(&key->k));
	jbyte *priv_data = (*env)->GetByteArrayElements(env, priv, NULL);
	pstm_to_unsigned_bin(NULL, &key->k, (unsigned char *) priv_data);
	(*env)->ReleaseByteArrayElements(env, priv, priv_data, 0);

	jint xlen = pstm_unsigned_bin_size(&key->pubkey.x);
	jint ylen = pstm_unsigned_bin_size(&key->pubkey.y);
	jbyteArray pub = (*env)->NewByteArray(env, 1 + xlen + ylen);
	jbyte *pub_data = (*env)->GetByteArrayElements(env, pub, NULL);
	pub_data[0] = 0x04;
	pstm_to_unsigned_bin(NULL, &key->pubkey.x, (unsigned char *) (pub_data + 1));
	pstm_to_unsigned_bin(NULL, &key->pubkey.y, (unsigned char *) (pub_data + 1 + xlen));
	(*env)->ReleaseByteArrayElements(env, pub, pub_data, 0);
	
	jobject ec_param_spec = create_ec_param_spec(env, curve);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub, ec_pub_param_spec);

	jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

	psEccDeleteKey(&key);

    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Matrixssl_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject this, jint keysize, jobject random) {
	size_t i = 0;
	while (eccCurves[i].size > 0) {
		if (eccCurves[i].size * 8 == keysize) {
			return generate_from_curve(env, &eccCurves[i]);
		}
		i++;
	}
	return NULL;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Matrixssl_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject this, jobject params, jobject random) {
    if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        psEccCurve_t *curve = create_curve(env, params);
        jobject result = generate_from_curve(env, curve);
        free_curve(curve);
        return result;
    } else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
		jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (*env)->CallObjectMethod(env, params, get_name);
        const char* utf_name = (*env)->GetStringUTFChars(env, name, NULL);
        size_t i = 0;
		while (eccCurves[i].size > 0) {
            if (strcasecmp(utf_name, eccCurves[i].name) == 0) {
                break;
            }
            i++;
        }
        (*env)->ReleaseStringUTFChars(env, name, utf_name);
        return generate_from_curve(env, &eccCurves[i]);
	} else {
		return NULL;
	}
}

static psEccKey_t *bytearray_to_privkey(JNIEnv *env, jbyteArray privkey, const psEccCurve_t *curve) {
	psEccKey_t *result;
	psEccNewKey(NULL, &result, curve);
	psEccInitKey(NULL, result, curve);

	pstm_init_for_read_unsigned_bin(NULL, &result->k, curve->size);
	jint len = (*env)->GetArrayLength(env, privkey);
	jbyte *priv_data = (*env)->GetByteArrayElements(env, privkey, NULL);
	pstm_read_unsigned_bin(&result->k, (unsigned char *) priv_data, len);
	(*env)->ReleaseByteArrayElements(env, privkey, priv_data, JNI_ABORT);
	result->type = PS_PRIVKEY;

	return result;
}

static psEccKey_t *bytearray_to_pubkey(JNIEnv *env, jbyteArray pubkey, const psEccCurve_t *curve) {
	psEccKey_t *result;
	psEccNewKey(NULL, &result, curve);
	psEccInitKey(NULL, result, curve);

	pstm_init_for_read_unsigned_bin(NULL, &result->pubkey.x, curve->size);
	pstm_init_for_read_unsigned_bin(NULL, &result->pubkey.y, curve->size);
	pstm_init_for_read_unsigned_bin(NULL, &result->pubkey.z, curve->size);
	jbyte *pubkey_data = (*env)->GetByteArrayElements(env, pubkey, NULL);
	pstm_read_unsigned_bin(&result->pubkey.x, (unsigned char *) (pubkey_data + 1), curve->size);
	pstm_read_unsigned_bin(&result->pubkey.y, (unsigned char *) (pubkey_data + 1 + curve->size), curve->size);
	(*env)->ReleaseByteArrayElements(env, pubkey, pubkey_data, JNI_ABORT);
	pstm_set(&result->pubkey.z, 1);
	result->type = PS_PUBKEY;

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Matrixssl_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params) {
	psEccCurve_t *curve = create_curve(env, params);

	psEccKey_t *priv = bytearray_to_privkey(env, privkey, curve);
	psEccKey_t *pub = bytearray_to_pubkey(env, pubkey, curve);

	jbyteArray result = (*env)->NewByteArray(env, curve->size);
	jbyte *result_data = (*env)->GetByteArrayElements(env, result, NULL);
	psSize_t outlen = curve->size;

	native_timing_start();
	int32_t err = psEccGenSharedSecret(NULL, priv, pub, (unsigned char *) result_data, &outlen, NULL);
	native_timing_stop();
	(*env)->ReleaseByteArrayElements(env, result, result_data, 0);

	psEccDeleteKey(&priv);
	psEccDeleteKey(&pub);
	free_curve(curve);

	if (err < 0) {
		throw_new(env, "java/security/GeneralSecurityException", "Couldn't derive secret.");
		return NULL;
	}

	return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Matrixssl_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Matrixssl_sign(JNIEnv *env, jobject this, jbyteArray data, jbyteArray privkey, jobject params) {
	psEccCurve_t *curve = create_curve(env, params);

	psEccKey_t *priv = bytearray_to_privkey(env, privkey, curve);

	psSize_t siglen = 512;
	uint8_t sig[siglen];

	jint data_len = (*env)->GetArrayLength(env, data);
	jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);
	native_timing_start();
	int32_t err = psEccDsaSign(NULL, priv, (unsigned char *) data_data, data_len, sig, &siglen, 0, NULL);
	native_timing_stop();

	psEccDeleteKey(&priv);
	free_curve(curve);

	if (err < 0) {
		throw_new(env, "java/security/GeneralSecurityException", "Couldn't sign data.");
		return NULL;
	}

	jbyteArray result = (*env)->NewByteArray(env, siglen);
	jbyte *result_data = (*env)->GetByteArrayElements(env, result, NULL);
	memcpy(result_data, sig, siglen);
	(*env)->ReleaseByteArrayElements(env, result, result_data, 0);

	return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Matrixssl_verify(JNIEnv *env, jobject this, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
	psEccCurve_t *curve = create_curve(env, params);
	psEccKey_t *pub = bytearray_to_pubkey(env, pubkey, curve);

	jint data_len = (*env)->GetArrayLength(env, data);
	jint sig_len = (*env)->GetArrayLength(env, signature);
	jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);
	jbyte *sig_data = (*env)->GetByteArrayElements(env, signature, NULL);

	int32_t result;
	native_timing_start();
	int32_t err = psEccDsaVerify(NULL, pub, (unsigned char *) data_data, data_len, (unsigned char *) sig_data, sig_len, &result, NULL);
	native_timing_stop();
	(*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, signature, sig_data, JNI_ABORT);

	free_curve(curve);
	psEccDeleteKey(&pub);

	if (err < 0) {
		throw_new(env, "java/security/GeneralSecurityException", "Couldn't verify signature.");
		return JNI_FALSE;
	}

	return result < 0 ? JNI_FALSE : JNI_TRUE;
}