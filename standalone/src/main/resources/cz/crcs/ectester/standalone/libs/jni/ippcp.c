#include "c_timing.h"
#include "c_utils.h"
#include "c_signals.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "native.h"

#include <ippcp.h>

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>

#define USE_SPEEDUP 1
#define VALIDATE_CURVE 1
#define VALIDATE_POINT 1

static IppsPRNGState *prng_state;
static jclass provider_class;

/* This needs to be specified in this way because ippcp does not offer functionality to retrieve
   information about supported curves in any way. */
typedef struct {
	const char name[128];
	IppECCType id;
	int size;
	const IppsGFpMethod* (*gfp_method_func)(void);
	IppStatus (*context_size_func)(int *);
	IppStatus (*init_func)(IppsECCPState *);
	IppStatus (*set_func)(IppsECCPState *);
	IppStatus (*precomp_func)(IppsECCPState *);
} ippcp_curve;

static const ippcp_curve CURVES[] = {
    {"secp112r1", IppECCPStd112r1, 112, NULL, NULL, NULL, NULL},
    {"secp112r2", IppECCPStd112r2, 112, NULL, NULL, NULL, NULL},
    {"secp128r1", IppECCPStd128r1, 128, NULL, NULL, NULL, NULL},
    {"secp128r2", IppECCPStd128r2, 128, NULL, NULL, NULL, NULL},
    {"secp160r1", IppECCPStd160r1, 160, NULL, NULL, NULL, NULL},
    {"secp160r2", IppECCPStd160r2, 160, NULL, NULL, NULL, NULL},
    {"secp192r1", IppECCPStd192r1, 192, ippsGFpMethod_p192r1, NULL, NULL, NULL},
    {"secp224r1", IppECCPStd224r1, 224, ippsGFpMethod_p224r1, NULL, NULL, NULL},
    {"secp256r1", IppECCPStd256r1, 256, ippsGFpMethod_p256r1, NULL, NULL, NULL},
    {"secp384r1", IppECCPStd384r1, 384, ippsGFpMethod_p384r1, NULL, NULL, NULL},
    {"secp521r1", IppECCPStd521r1, 521, ippsGFpMethod_p521r1, NULL, NULL, NULL}};

static const int NUM_CURVES = sizeof(CURVES) / sizeof(ippcp_curve);

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_IppcpLib_createProvider(JNIEnv *env, jobject this) {
	/* Create the custom provider. */
	jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Ippcp");
	provider_class = (*env)->NewGlobalRef(env, local_provider_class);

	jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

	const CryptoLibraryVersion *lib = cryptoGetLibVersion();
	jstring name = (*env)->NewStringUTF(env, lib->name);
	double version = (double)lib->major + ((double)lib->minor / 10);
	jstring info = (*env)->NewStringUTF(env, lib->strVersion);

	return (*env)->NewObject(env, provider_class, init, name, version, info);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Ippcp_setup(JNIEnv *env, jobject this) {
	INIT_PROVIDER(env, provider_class);

	ADD_KPG(env, this, "EC", "Ippcp");
	ADD_KA(env, this, "ECDH", "IppcpECDH");
	ADD_SIG(env, this, "NONEwithECDSA", "IppcpECDSAwithNONE");

	/* Init the PRNG. */
	int prng_size;
	ippsPRNGGetSize(&prng_size);
	prng_state = malloc(prng_size);
	ippsPRNGInit(160, prng_state);
	/* We need to manually seed the PRNG, let's hope that everyone using ippcp does this.
	   Otherwise: nonce reuse in ECDSA, whoops! */
	int seed_len = 8;
	Ipp32u seed[seed_len];
	IppStatus res = ippsTRNGenRDSEED(seed, sizeof(seed) * 8, NULL);
	if (res != ippStsNoErr) {
		res = ippsPRNGenRDRAND(seed, sizeof(seed) * 8, NULL);
	}
	if (res != ippStsNoErr) {
		FILE *urandom = fopen("/dev/urandom", "rb");
		if (urandom) {
			size_t read = 0;
			while (read < sizeof(seed)) {
				read += fread(((uint8_t *)&seed) + read, 1, sizeof(seed) - read, urandom);
			}
			fclose(urandom);
			res = ippStsNoErr;
		}
	}
	if (res != ippStsNoErr) {
		struct timespec t;
		if (!clock_gettime(CLOCK_REALTIME, &t)) {
			memcpy(seed, &t.tv_nsec, sizeof(t.tv_nsec) > sizeof(seed) ? sizeof(seed) : sizeof(t.tv_nsec));
		} else {
			time_t tim = time(NULL);
			memcpy(seed, &tim, sizeof(time_t) > sizeof(seed) ? sizeof(seed) : sizeof(time_t));
		}
	}
	int bn_size;
	ippsBigNumGetSize(seed_len, &bn_size);
	uint8_t bn_buf[bn_size];
	IppsBigNumState *bn = (IppsBigNumState *)bn_buf;
	ippsBigNumInit(seed_len, bn);
	ippsSet_BN(IppsBigNumPOS, seed_len, seed, bn);
	ippsPRNGSetSeed(bn, prng_state);

	init_classes(env, "Ippcp");
}

static IppStatus prng_wrapper(Ipp32u *pRand, int nBits, void *pCtx) {
	native_timing_pause();
	IppStatus result = ippsPRNGen(pRand, nBits, pCtx);
	native_timing_restart();
	return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_IppcpLib_getCurves(JNIEnv *env, jobject this) {
	jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

	jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
	jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

	jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);

	for (size_t i = 0; i < NUM_CURVES; ++i) {
		jstring curve_name = (*env)->NewStringUTF(env, CURVES[i].name);
		(*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
	}
	return result;
}


JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_IppcpLib_supportsDeterministicPRNG(JNIEnv *env, jobject self) {
	return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_IppcpLib_setupDeterministicPRNG(JNIEnv *env, jobject self, jbyteArray seed) {
	jsize seed_length = (*env)->GetArrayLength(env, seed);
	if (seed_length % 4 != 0) {
		fprintf(stderr, "Error setting seed, needs to be a multiple of 4 bytes.\n");
		return JNI_FALSE;
	}
	int bn_size;
	ippsBigNumGetSize(seed_length / 4, &bn_size);
	uint8_t bn_buf[bn_size];
	IppsBigNumState *bn = (IppsBigNumState *)bn_buf;
	ippsBigNumInit(seed_length / 4, bn);
	jbyte *seed_data = (*env)->GetByteArrayElements(env, seed, NULL);
	ippsSet_BN(IppsBigNumPOS, seed_length / 4, (Ipp32u *) seed_data, bn);
	ippsPRNGSetSeed(bn, prng_state);
	(*env)->ReleaseByteArrayElements(env, seed, seed_data, JNI_ABORT);
	return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Ippcp_keysizeSupported(JNIEnv *env,
                                                                                                                           jobject this,
                                                                                                                           jint keysize) {
	for (size_t i = 0; i < NUM_CURVES; ++i) {
		if (CURVES[i].size == keysize) {
			return JNI_TRUE;
		}
	}
	return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Ippcp_paramsSupported(JNIEnv *env,
                                                                                                                          jobject this,
                                                                                                                          jobject params) {
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
		for (size_t i = 0; i < NUM_CURVES; ++i) {
			if (strcasecmp(utf_name, CURVES[i].name) == 0) {
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


static IppsGFpECPoint *new_point(IppsGFpECState *ec) {
	int point_size;
	ippsGFpECPointGetSize(ec, &point_size);
	IppsGFpECPoint *point = malloc(point_size);
	ippsGFpECPointInit(NULL, NULL, point, ec);
	return point;
}

#define BITS_TO_I32(bits) ((bits + 7) / 8) / sizeof(Ipp32u)

static IppsBigNumState *new_bn(int bits) {
	int bn_size;
	int len = BITS_TO_I32(bits);
	ippsBigNumGetSize(len, &bn_size);
	IppsBigNumState *bn = malloc(bn_size);
	ippsBigNumInit(len, bn);
	return bn;
}

static void bn_get(IppsBigNumState *bn, uint8_t *buf, int lsb) {
	int size;
	ippsGetSize_BN(bn, &size);
	size *= sizeof(Ipp32u);
	uint8_t data[size];
	ippsGetOctString_BN(data, size, bn);
	memcpy(buf, data + (size - lsb), lsb);
}

static jobject bn_to_biginteger(JNIEnv *env, const IppsBigNumState *bn) {
	jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
	int bn_size;
	ippsGetSize_BN(bn, &bn_size);
	bn_size *= sizeof(Ipp32u);
	jbyteArray bytes = (*env)->NewByteArray(env, bn_size);
	jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
	ippsGetOctString_BN((Ipp8u *) data, bn_size, bn);
	(*env)->ReleaseByteArrayElements(env, bytes, data, 0);
	jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
	return result;
}

static IppsBigNumState *biginteger_to_bn(JNIEnv *env, jobject bigint) {
	jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");

    jbyteArray byte_array = (jbyteArray) (*env)->CallObjectMethod(env, bigint, to_byte_array);
    jsize byte_length = (*env)->GetArrayLength(env, byte_array);
    jbyte *byte_data = (*env)->GetByteArrayElements(env, byte_array, NULL);
	IppsBigNumState *result = new_bn(byte_length * 8);
	ippsSetOctString_BN((Ipp8u *) byte_data, byte_length, result);
	(*env)->ReleaseByteArrayElements(env, byte_array, byte_data, JNI_ABORT);
	return result;
}

static IppsGFpElement *biginteger_to_gfp_elem(JNIEnv *env, jobject bigint, IppsGFpState *gf, jint bits, int elem_size) {
	IppsBigNumState *bn = biginteger_to_bn(env, bigint);
	IppsGFpElement *result = malloc(elem_size);
	ippsGFpSetElementRegular(bn, result, gf);
	return result;
}

static jobject gfp_elem_to_biginteger(JNIEnv *env, const IppsGFpElement *elem, IppsGFpState *gf, jint bits) {
	int bn_size = BITS_TO_I32(bits) * sizeof(Ipp32u);
	jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
	jbyteArray bytes = (*env)->NewByteArray(env, bn_size);
	jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
	ippsGFpGetElementOctString(elem, data, bn_size, gf);
	(*env)->ReleaseByteArrayElements(env, bytes, data, 0);
	jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
	return result;
}

/*
static void biginteger_print(JNIEnv *env, jobject bigint) {
    jmethodID to_string = (*env)->GetMethodID(env, biginteger_class, "toString", "(I)Ljava/lang/String;");
    jstring big_string = (*env)->CallObjectMethod(env, bigint, to_string, (jint) 16);

    jsize len = (*env)->GetStringUTFLength(env, big_string);
    char raw_string[len + 1];
    raw_string[len] = 0;
    (*env)->GetStringUTFRegion(env, big_string, 0, len, raw_string);
    printf("%s\n", raw_string);
    fflush(stdout);
}
*/

static IppsECCPState *create_curve(JNIEnv *env, jobject params, int *keysize) {
	jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
    jobject curve = (*env)->CallObjectMethod(env, params, get_curve);

    jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
    jobject field = (*env)->CallObjectMethod(env, curve, get_field);

	if (!(*env)->IsInstanceOf(env, field, fp_field_class)) {
		return NULL;
	}

	jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
    jint bits = (*env)->CallIntMethod(env, field, get_bits);

    jmethodID get_p = (*env)->GetMethodID(env, fp_field_class, "getP", "()Ljava/math/BigInteger;");
    jobject p = (*env)->CallObjectMethod(env, field, get_p);
	IppsBigNumState *p_bn = biginteger_to_bn(env, p);

	const IppsGFpMethod *method = ippsGFpMethod_pArb();
	int gfp_size;
	IppStatus err = ippsGFpGetSize(bits, &gfp_size);
	if (err != ippStsNoErr) {
		goto err_out;
	}
	IppsGFpState *gf = malloc(gfp_size);
	err = ippsGFpInit(p_bn, bits, method, gf);
	if (err != ippStsNoErr) {
		free(gf);
		goto err_out;
	}
	int elem_size;
	err = ippsGFpElementGetSize(gf, &elem_size);
	if (err != ippStsNoErr) {
		free(gf);
		goto err_out;
	}

	jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
    jobject a = (*env)->CallObjectMethod(env, curve, get_a);
    IppsGFpElement *a_elem = biginteger_to_gfp_elem(env, a, gf, bits, elem_size);
    if (!a_elem) {
		goto err_out;
    }

    jmethodID get_b = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
    jobject b = (*env)->CallObjectMethod(env, curve, get_b);
    IppsGFpElement *b_elem = biginteger_to_gfp_elem(env, b, gf, bits, elem_size);
    if (!b_elem) {
		goto err_out;
    }

	jmethodID get_g = (*env)->GetMethodID(env, ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
    jobject g = (*env)->CallObjectMethod(env, params, get_g);

    jmethodID get_x = (*env)->GetMethodID(env, point_class, "getAffineX", "()Ljava/math/BigInteger;");
    jobject gx = (*env)->CallObjectMethod(env, g, get_x);
    IppsGFpElement *gx_elem = biginteger_to_gfp_elem(env, gx, gf, bits, elem_size);
    if (!gx_elem) {
		goto err_out;
    }

    jmethodID get_y = (*env)->GetMethodID(env, point_class, "getAffineY", "()Ljava/math/BigInteger;");
    jobject gy = (*env)->CallObjectMethod(env, g, get_y);
    IppsGFpElement *gy_elem = biginteger_to_gfp_elem(env, gy, gf, bits, elem_size);
    if (!gy_elem) {
		goto err_out;
    }

	jmethodID get_n = (*env)->GetMethodID(env, ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
    jobject n = (*env)->CallObjectMethod(env, params, get_n);
	IppsBigNumState *n_bn = biginteger_to_bn(env, n);

	jmethodID get_h = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCofactor", "()I");
	jint h = (*env)->CallIntMethod(env, params, get_h);
	IppsBigNumState *h_bn = new_bn(32);
	ippsSet_BN(IppsBigNumPOS, 1, (Ipp32u *) &h, h_bn);

	if (keysize) {
		*keysize = bits;
	}

	int size;
	err = ippsGFpECGetSize(gf, &size);
	if (err != ippStsNoErr) {
		goto err_out;
	}
	IppsGFpECState *result = malloc(size);
	err = ippsGFpECInit(gf, a_elem, b_elem, result);
	if (err != ippStsNoErr) {
		free(result);
		goto err_out;
	}
	err = ippsGFpECSetSubgroup(gx_elem, gy_elem, n_bn, h_bn, result);
	if (err != ippStsNoErr) {
		free(result);
		goto err_out;
	}

	return result;
err_out:
	if (p_bn)
		free(p_bn);
	if (a_elem)
		free(a_elem);
	if (b_elem)
		free(b_elem);
	if (gx_elem)
		free(gx_elem);
	if (gy_elem)
		free(gy_elem);
	if (n_bn)
		free(n_bn);
	if (h_bn)
		free(h_bn);
	return NULL;
}

static jobject create_ec_param_spec(JNIEnv *env, int keysize, IppsGFpECState *curve) {
	IppStatus err;

	IppsGFpState *gf;

	err = ippsGFpECGet(&gf, NULL, NULL, curve);
	int elem_size;
	err = ippsGFpElementGetSize(gf, &elem_size);
	jmethodID biginteger_valueof = (*env)->GetStaticMethodID(env, biginteger_class, "valueOf", "(J)Ljava/math/BigInteger;");
	jobject zero = (*env)->CallStaticObjectMethod(env, biginteger_class, biginteger_valueof, (jlong)0);
	jobject one = (*env)->CallStaticObjectMethod(env, biginteger_class, biginteger_valueof, (jlong)1);
	IppsGFpElement *zero_elem = biginteger_to_gfp_elem(env, zero, gf, keysize, elem_size);
	IppsGFpElement *one_elem = biginteger_to_gfp_elem(env, one, gf, keysize, elem_size);
	IppsGFpElement *pm1_elem = malloc(elem_size);
	ippsGFpElementInit(NULL, 0, pm1_elem, gf);
	ippsGFpSub(zero_elem, one_elem, pm1_elem, gf);
	free(zero_elem);
	free(one_elem);

	jobject pm1 = gfp_elem_to_biginteger(env, pm1_elem, gf, keysize);
	free(pm1_elem);
	jmethodID biginteger_add = (*env)->GetMethodID(env, biginteger_class, "add", "(Ljava/math/BigInteger;)Ljava/math/BigInteger;");
	jobject p = (*env)->CallObjectMethod(env, pm1, biginteger_add, one);

	IppsGFpElement *a_elem = malloc(elem_size);
	ippsGFpElementInit(NULL, 0, a_elem, gf);
	IppsGFpElement *b_elem = malloc(elem_size);
	ippsGFpElementInit(NULL, 0, b_elem, gf);
	err = ippsGFpECGet(&gf, a_elem, b_elem, curve);

	IppsGFpElement *gx_elem = malloc(elem_size);
	ippsGFpElementInit(NULL, 0, gx_elem, gf);
	IppsGFpElement *gy_elem = malloc(elem_size);
	ippsGFpElementInit(NULL, 0, gy_elem, gf);

	int ord_size;
	ippsBigNumGetSize((keysize + 32) / 32, &ord_size);
	IppsBigNumState *order_bn = malloc(ord_size);
	ippsBigNumInit(ord_size, order_bn);
	IppsBigNumState *cofactor_bn = malloc(4);
	ippsBigNumInit(4, cofactor_bn);
	err = ippsGFpECGetSubgroup(&gf, gx_elem, gy_elem, order_bn, cofactor_bn, curve);
	
    jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject field = (*env)->NewObject(env, fp_field_class, fp_field_init, p);
	
	jobject a = gfp_elem_to_biginteger(env, a_elem, gf, keysize);
	jobject b = gfp_elem_to_biginteger(env, b_elem, gf, keysize);
	free(a_elem);
	free(b_elem);

	jmethodID elliptic_curve_init = (*env)->GetMethodID(env, elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = (*env)->NewObject(env, elliptic_curve_class, elliptic_curve_init, field, a, b);

	jobject gx = gfp_elem_to_biginteger(env, gx_elem, gf, keysize);
	jobject gy = gfp_elem_to_biginteger(env, gy_elem, gf, keysize);
	jmethodID point_init = (*env)->GetMethodID(env, point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject g = (*env)->NewObject(env, point_class, point_init, gx, gy);
	free(gx_elem);
	free(gy_elem);

	jobject n = bn_to_biginteger(env, order_bn);
	free(order_bn);

	jmethodID ec_parameter_spec_init = (*env)->GetMethodID(env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    return (*env)->NewObject(env, ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, n, cofactor);
}

static jobject generate_from_curve(JNIEnv *env, int keysize, IppsECCPState *curve) {
	if (VALIDATE_CURVE) {
		IppECResult validation;
		ippsECCPValidate(50, &validation, curve, ippsPRNGen, prng_state);
		if (validation != ippECValid) {
			throw_new(env, "java/security/GeneralSecurityException", ippsECCGetResultString(validation));
			return NULL;
		}
	}

	IppsECCPPointState *point = new_point(keysize);

	int ord_bits;
	ippsECCPGetOrderBitSize(&ord_bits, curve);
	int ord_bytes = (ord_bits + 7) / 8;
	IppsBigNumState *secret = new_bn(ord_bits);

	IppStatus err;
	SIG_TRY(TIMEOUT) {
		native_timing_start();
		err = ippsECCPGenKeyPair(secret, point, curve, prng_wrapper, prng_state);
		native_timing_stop();
	} SIG_CATCH_HANDLE(env);

	if (err != ippStsNoErr) {
		throw_new(env, "java/security/GeneralSecurityException", ippcpGetStatusString(err));
		free(point);
		free(secret);
		return NULL;
	}

	int coord_bytes = (keysize + 7) / 8;
	IppsBigNumState *x = new_bn(keysize);
	IppsBigNumState *y = new_bn(keysize);

	ippsECCPGetPoint(x, y, point, curve);

	jbyteArray pub_bytes = (*env)->NewByteArray(env, 2 * coord_bytes + 1);
	jbyte *pub_data = (*env)->GetByteArrayElements(env, pub_bytes, NULL);
	pub_data[0] = 0x04;
	bn_get(x, (uint8_t *) (pub_data + 1), coord_bytes);
	bn_get(y, (uint8_t *) (pub_data + 1 + coord_bytes), coord_bytes);
	(*env)->ReleaseByteArrayElements(env, pub_bytes, pub_data, 0);

	jbyteArray priv_bytes = (*env)->NewByteArray(env, ord_bytes);
	jbyte *priv_data = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
	bn_get(secret, (uint8_t *) priv_data, ord_bytes);
	(*env)->ReleaseByteArrayElements(env, priv_bytes, priv_data, 0);

	free(point);
	free(secret);
	free(x);
	free(y);

	jobject ec_param_spec = create_ec_param_spec(env, keysize, curve);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, pub_bytes, ec_pub_param_spec);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

static jobject generate_from_curve_info(JNIEnv *env, const ippcp_curve *curve_info) {
	int context_size;
	if (curve_info->context_size_func) {
		curve_info->context_size_func(&context_size);
	} else {
		ippsECCPGetSize(curve_info->size, &context_size);
	}
	uint8_t curve_buf[context_size];
	IppsECCPState *curve = (IppsECCPState *)curve_buf;
	if (curve_info->init_func) {
		curve_info->init_func(curve);
	} else {
		ippsECCPInit(curve_info->size, curve);
	}
	if (curve_info->set_func) {
		curve_info->set_func(curve);
	} else {
		ippsECCPSetStd(curve_info->id, curve);
	}
	if (USE_SPEEDUP && curve_info->precomp_func) {
		curve_info->precomp_func(curve);
	}
	return generate_from_curve(env, curve_info->size, curve);
}

JNIEXPORT jobject JNICALL
Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Ippcp_generate__ILjava_security_SecureRandom_2(JNIEnv *env,
                                                                                                                        jobject this,
                                                                                                                        jint keysize,
                                                                                                                        jobject random) {
	for (size_t i = 0; i < NUM_CURVES; ++i) {
		if (CURVES[i].size == keysize) {
			return generate_from_curve_info(env, &CURVES[i]);
		}
	}
	return NULL;
}

JNIEXPORT jobject JNICALL
Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Ippcp_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(
    JNIEnv *env, jobject this, jobject params, jobject random) {

	if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
		int keysize;
		IppsECCPState *curve = create_curve(env, params, &keysize);
		if (!curve) {
			throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
			return NULL;
		}
		jobject result = generate_from_curve(env, keysize, curve);
		free(curve);
		return result;
	} else if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
		jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
		jstring name = (*env)->CallObjectMethod(env, params, get_name);
		const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
		const ippcp_curve *curve_info;
		for (size_t i = 0; i < NUM_CURVES; ++i) {
			if (strcasecmp(utf_name, CURVES[i].name) == 0) {
				curve_info = &CURVES[i];
				break;
			}
		}
		(*env)->ReleaseStringUTFChars(env, name, utf_name);
		return generate_from_curve_info(env, curve_info);
	} else {
		return NULL;
	}
}

static IppsECCPPointState *bytearray_to_pubkey(JNIEnv *env, jbyteArray pubkey, jint keysize, IppsECCPState *curve) {
	IppsBigNumState *x_bn = new_bn(keysize);
	IppsBigNumState *y_bn = new_bn(keysize);

	jint coord_size = (keysize + 7) / 8;
	jbyte *pub_data = (*env)->GetByteArrayElements(env, pubkey, NULL);
	ippsSetOctString_BN((Ipp8u *) (pub_data + 1), coord_size, x_bn);
	ippsSetOctString_BN((Ipp8u *) (pub_data + 1 + coord_size), coord_size, y_bn);
	(*env)->ReleaseByteArrayElements(env, pubkey, pub_data, JNI_ABORT);

	IppsECCPPointState *pub = new_point(keysize);
	ippsECCPSetPoint(x_bn, y_bn, pub, curve);
	free(x_bn);
	free(y_bn);
	return pub;
}

static IppsBigNumState *bytearray_to_privkey(JNIEnv *env, jbyteArray privkey, IppsECCPState *curve) {
	int ord_bits;
	ippsECCPGetOrderBitSize(&ord_bits, curve);
	IppsBigNumState *priv_bn = new_bn(ord_bits);
	jbyte *priv_data = (*env)->GetByteArrayElements(env, privkey, NULL);
	ippsSetOctString_BN((Ipp8u *) priv_data, (*env)->GetArrayLength(env, privkey), priv_bn);
	(*env)->ReleaseByteArrayElements(env, privkey, priv_data, JNI_ABORT);
	return priv_bn;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Ippcp_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params) {
	jint coord_size = ((*env)->GetArrayLength(env, pubkey) - 1) / 2;
	jint keysize;
	IppsECCPState *curve = create_curve(env, params, &keysize);
	if (!curve) {
		throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
		return NULL;
	}

	if (VALIDATE_CURVE) {
		IppECResult validation;
		ippsECCPValidate(50, &validation, curve, ippsPRNGen, prng_state);
		if (validation != ippECValid) {
			throw_new(env, "java/security/GeneralSecurityException", ippsECCGetResultString(validation));
			free(curve);
			return NULL;
		}
	}
	IppsECCPPointState *pub = bytearray_to_pubkey(env, pubkey, keysize, curve);

	if (VALIDATE_POINT) {
		IppECResult validation;
		ippsECCPCheckPoint(pub, &validation, curve);
		if (validation != ippECValid) {
			throw_new(env, "java/security/GeneralSecurityException", ippsECCGetResultString(validation));
			free(curve);
			free(pub);
			return NULL;
		}
	}

	IppsBigNumState *priv_bn = bytearray_to_privkey(env, privkey, curve);

	IppsBigNumState *share = new_bn(keysize);

	IppStatus err;
	SIG_TRY(TIMEOUT) {
		native_timing_start();
		err = ippsECCPSharedSecretDH(priv_bn, pub, share, curve);
		native_timing_stop();
	} SIG_CATCH_HANDLE(env);

	free(priv_bn);
	free(pub);
	free(curve);

	if (err != ippStsNoErr) {
		throw_new(env, "java/security/GeneralSecurityException", ippcpGetStatusString(err));
		return NULL;
	}

	jbyteArray result = (*env)->NewByteArray(env, coord_size);
	jbyte *data = (*env)->GetByteArrayElements(env, result, NULL);
	bn_get(share, (uint8_t *) data, coord_size);
	(*env)->ReleaseByteArrayElements(env, result, data, 0);
	free(share);
	return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Ippcp_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject this, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Ippcp_sign(JNIEnv *env, jobject this, jbyteArray data, jbyteArray privkey, jobject params) {
	jint keysize;
	IppsECCPState *curve = create_curve(env, params, &keysize);
	if (!curve) {
		throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
		return NULL;
	}

	if (VALIDATE_CURVE) {
		IppECResult validation;
		ippsECCPValidate(50, &validation, curve, ippsPRNGen, prng_state);
		if (validation != ippECValid) {
			throw_new(env, "java/security/GeneralSecurityException", ippsECCGetResultString(validation));
			free(curve);
			return NULL;
		}
	}
	IppsBigNumState *priv_bn = bytearray_to_privkey(env, privkey, curve);

	IppsECCPPointState *ephemeral_point = new_point(keysize);
	int ord_bits;
	ippsECCPGetOrderBitSize(&ord_bits, curve);
	int ord_bytes = (ord_bits + 7) / 8;
	IppsBigNumState *ephemeral_secret = new_bn(ord_bits);
	IppsBigNumState *r = new_bn(ord_bits);
	IppsBigNumState *s = new_bn(ord_bits);

	jint data_size = (*env)->GetArrayLength(env, data);
	IppsBigNumState *data_bn = new_bn(data_size * 8);
	jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);
	ippsSetOctString_BN((Ipp8u *) data_data, data_size, data_bn);
	(*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);

	jbyteArray result = NULL;
	jbyte r_buf[ord_bytes];
	jbyte s_buf[ord_bytes];

	IppStatus err;
	SIG_TRY(TIMEOUT) {
		native_timing_start();
		err = ippsECCPGenKeyPair(ephemeral_secret, ephemeral_point, curve, prng_wrapper, prng_state);
		if (err != ippStsNoErr) {
			SIG_DEINIT();
			throw_new(env, "java/security/GeneralSecurityException", ippcpGetStatusString(err));
			goto error;
		}
		err = ippsECCPSetKeyPair(ephemeral_secret, ephemeral_point, ippFalse, curve);
		if (err != ippStsNoErr) {
			SIG_DEINIT();
			throw_new(env, "java/security/GeneralSecurityException", ippcpGetStatusString(err));
			goto error;
		}
		err = ippsGFpECSignDSA(data_bn, priv_bn, r, s, curve);
		if (err != ippStsNoErr) {
			SIG_DEINIT();
			throw_new(env, "java/security/GeneralSecurityException", ippcpGetStatusString(err));
			goto error;
		}
		native_timing_stop();
	} SIG_CATCH_HANDLE(env);

	bn_get(r, (uint8_t *) r_buf, ord_bytes);
	bn_get(s, (uint8_t *) s_buf, ord_bytes);

	result = asn1_der_encode(env, r_buf, ord_bytes, s_buf, ord_bytes);

error:
	free(curve);
	free(priv_bn);
	free(ephemeral_point);
	free(ephemeral_secret);
	free(r);
	free(s);
	return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Ippcp_verify(JNIEnv *env, jobject this, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
	jint keysize;
	IppsECCPState *curve = create_curve(env, params, &keysize);
	if (!curve) {
		throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
		return JNI_FALSE;
	}

	if (VALIDATE_CURVE) {
		IppECResult validation;
		int buffer_size;
		ippsGFpECScratchBufferSize(4, curve, &buffer_size);
		Ipp8u *scratch = malloc(buffer_size);
		ippsGFpECVerify(&validation, curve, scratach);
		free(scratch);
		if (validation != ippECValid) {
			throw_new(env, "java/security/GeneralSecurityException", ippsECCGetResultString(validation));
			free(curve);
			return JNI_FALSE;
		}
	}
	IppsECCPPointState *pub = bytearray_to_pubkey(env, pubkey, keysize, curve);

	if (VALIDATE_POINT) {
		IppECResult validation;
		ippsGFpECTstPoint(pub, &validation, curve);
		if (validation != ippECValid) {
			throw_new(env, "java/security/GeneralSecurityException", ippsECCGetResultString(validation));
			free(curve);
			free(pub);
			return JNI_FALSE;
		}
	}

    size_t r_len, s_len;
    jbyte *r_data, *s_data;
    bool decode = asn1_der_decode(env, signature, &r_data, &r_len, &s_data, &s_len);
	if (!decode) {
		throw_new(env, "java/security/GeneralSecurityException", "Error decoding sig.");
		free(curve);
		free(pub);
		return JNI_FALSE;
	}

	int ord_bits;
	ippsECCPGetOrderBitSize(&ord_bits, curve);

	IppsBigNumState *r = new_bn(ord_bits);
	ippsSetOctString_BN((Ipp8u *) r_data, r_len, r);
	free(r_data);
	IppsBigNumState *s = new_bn(ord_bits);
	ippsSetOctString_BN((Ipp8u *) s_data, s_len, s);
	free(s_data);

	jint data_size = (*env)->GetArrayLength(env, data);
	IppsBigNumState *data_bn = new_bn(data_size * 8);
	jbyte *data_data = (*env)->GetByteArrayElements(env, data, NULL);
	ippsSetOctString_BN((Ipp8u *) data_data, data_size, data_bn);
	(*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);

	IppECResult result;

	IppStatus err;
	SIG_TRY(TIMEOUT) {
		native_timing_start();
		ippsECCPSetKeyPair(NULL, pub, ippTrue, curve);
		err = ippsECCPVerifyDSA(data_bn, r, s, &result, curve);
		native_timing_stop();
	} SIG_CATCH_HANDLE(env);

	free(curve);
	free(pub);
	free(r);
	free(s);

	if (err == ippStsNoErr && result == ippECValid) {
		return JNI_TRUE;
	}
	if (err != ippStsNoErr) {
		throw_new(env, "java/security/GeneralSecurityException", ippcpGetStatusString(err));
		return JNI_FALSE;
	}

	return JNI_FALSE;
}