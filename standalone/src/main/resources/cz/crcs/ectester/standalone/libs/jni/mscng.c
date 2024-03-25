#include <windows.h>
#include <bcrypt.h>
#include "native.h"

#include "c_timing.h"
#include "c_utils.h"

// BCRYPT and NT things.
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define NT_FAILURE(status) !NT_SUCCESS(status)

#define STATUS_SUCCESS 0x00000000
#define STATUS_INVALID_SIGNATURE 0xC000A000

typedef struct {
	ULONG dwVersion;                  // Version of the structure
	ECC_CURVE_TYPE_ENUM dwCurveType;  // Supported curve types.
	ECC_CURVE_ALG_ID_ENUM dwCurveGenerationAlgId;  // For X.592 verification purposes, if we include Seed we will need to include the algorithm ID.
	ULONG cbFieldLength;         // Byte length of the fields P, A, B, X, Y.
	ULONG cbSubgroupOrder;       // Byte length of the subgroup.
	ULONG cbCofactor;            // Byte length of cofactor of G in E.
	ULONG cbSeed;                // Byte length of the seed used to generate the curve.
} BCRYPT_ECC_PARAMETER_HEADER;

// Provider things
static jclass provider_class;

#define KEYFLAG_IMPLICIT 0  // Mscng native key, over named curve
#define KEYFLAG_EXPLICIT 1  // Mscng native key, over explicit ecc parameters
#define KEYFLAG_NIST 2      // Mscng native key, over NIST parameters, custom ECDH/ECDSA_P* algo
#define KEYFLAG_OTHER 3     // Other key, explicit ecc parameters

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MscngLib_createProvider(JNIEnv *env, jobject self) {
	jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Mscng");
	provider_class = (*env)->NewGlobalRef(env, local_provider_class);

	jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

	jstring name = (*env)->NewStringUTF(env, "Microsoft CNG");
	double version = 1.0;

	return (*env)->NewObject(env, provider_class, init, name, version, name);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Mscng_setup(JNIEnv *env, jobject self) {
	INIT_PROVIDER(env, provider_class);

	ADD_KPG(env, self, "ECDH", "MscngECDH");
	ADD_KPG(env, self, "ECDSA", "MscngECDSA");

	ADD_KA(env, self, "ECDHwithSHA1KDF(CNG)", "MscngECDHwithSHA1KDF");
	ADD_KA(env, self, "ECDHwithSHA256KDF(CNG)", "MscngECDHwithSHA256KDF");
	ADD_KA(env, self, "ECDHwithSHA384KDF(CNG)", "MscngECDHwithSHA384KDF");
	ADD_KA(env, self, "ECDHwithSHA512KDF(CNG)", "MscngECDHwithSHA512KDF");

	ADD_SIG(env, self, "SHA1withECDSA", "MscngECDSAwithSHA1");
	ADD_SIG(env, self, "SHA256withECDSA", "MscngECDSAwithSHA256");
	ADD_SIG(env, self, "SHA384withECDSA", "MscngECDSAwithSHA384");
	ADD_SIG(env, self, "SHA512withECDSA", "MscngECDSAwithSHA112");

	init_classes(env, "Mscng");
}

typedef struct {
	LPCSTR name;
	ULONG bits;
} named_curve_t;

static named_curve_t named_curves[] = {
    {"curve25519", 256},      {"brainpoolP160r1", 160}, {"brainpoolP160t1", 160}, {"brainpoolP192r1", 192}, {"brainpoolP192t1", 192},
    {"brainpoolP224r1", 224}, {"brainpoolP224t1", 224}, {"brainpoolP256r1", 256}, {"brainpoolP256t1", 256}, {"brainpoolP320r1", 320},
    {"brainpoolP320t1", 320}, {"brainpoolP384r1", 384}, {"brainpoolP384t1", 384}, {"brainpoolP512r1", 512}, {"brainpoolP512t1", 512},
    {"ec192wapi", 192},       {"nistP192", 192},        {"nistP224", 224},        {"nistP256", 256},        {"nistP384", 384},
    {"nistP521", 521},        {"numsP256t1", 256},      {"numsP384t1", 384},      {"numsP512t1", 512},      {"secP160k1", 160},
    {"secP160r1", 160},       {"secP160r2", 160},       {"secP192k1", 192},       {"secP192r1", 192},       {"secP224k1", 224},
    {"secP224r1", 224},       {"secP256k1", 256},       {"secP256r1", 256},       {"secP384r1", 384},       {"secP521r1", 521},
    {"wtls12", 224},          {"wtls7", 160},           {"wtls9", 160},           {"x962P192v1", 192},      {"x962P192v2", 192},
    {"x962P192v3", 192},      {"x962P239v1", 239},      {"x962P239v2", 239},      {"x962P239v3", 239},      {"x962P256v1", 256}};

static const named_curve_t *lookup_curve(const char *name) {
	for (size_t i = 0; i < sizeof(named_curves) / sizeof(named_curve_t); ++i) {
		if (strcmp(name, named_curves[i].name) == 0) {
			return &named_curves[i];
		}
	}
	return NULL;
}

static ULONG utf_16to8(NPSTR *out_buf, LPCWSTR in_str) {
	INT result = WideCharToMultiByte(CP_UTF8, 0, in_str, -1, NULL, 0, NULL, NULL);
	*out_buf = calloc(result, 1);
	return WideCharToMultiByte(CP_UTF8, 0, in_str, -1, *out_buf, result, NULL, NULL);
}

static ULONG utf_8to16(NWPSTR *out_buf, LPCSTR in_str) {
	INT result = MultiByteToWideChar(CP_UTF8, 0, in_str, -1, NULL, 0);
	*out_buf = calloc(result * sizeof(WCHAR), 1);
	return MultiByteToWideChar(CP_UTF8, 0, in_str, -1, *out_buf, result);
}

/**
 * Convert Java String to UTF-16 NWPSTR null-terminated.
 * Returns: Length of NWPSTR in bytes!
 */
static ULONG utf_strto16(NWPSTR *out_buf, JNIEnv *env, jobject str) {
	jsize len = (*env)->GetStringLength(env, str);
	*out_buf = calloc(len * sizeof(jchar) + 1, 1);
	const jchar *chars = (*env)->GetStringChars(env, str, NULL);
	memcpy(*out_buf, chars, len * sizeof(jchar));
	(*env)->ReleaseStringChars(env, str, chars);
	return len * sizeof(jchar);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MscngLib_getCurves(JNIEnv *env, jobject self) {
	jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

	jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
	jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

	jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);

	NTSTATUS status;
	BCRYPT_ALG_HANDLE handle;

	if (NT_FAILURE(status = BCryptOpenAlgorithmProvider(&handle, BCRYPT_ECDH_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		return result;
	}

	ULONG bufSize;
	if (NT_FAILURE(status = BCryptGetProperty(handle, BCRYPT_ECC_CURVE_NAME_LIST, NULL, 0, &bufSize, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty(length only)\n", status);
		BCryptCloseAlgorithmProvider(handle, 0);
		return result;
	}

	BCRYPT_ECC_CURVE_NAMES *curves = (BCRYPT_ECC_CURVE_NAMES *)calloc(bufSize, 1);
	if (NT_FAILURE(status = BCryptGetProperty(handle, BCRYPT_ECC_CURVE_NAME_LIST, (PBYTE)curves, bufSize, &bufSize, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty(whole)\n", status);
		BCryptCloseAlgorithmProvider(handle, 0);
		free(curves);
		return result;
	}

	for (size_t i = 0; i < curves->dwEccCurveNames; ++i) {
		NPSTR curve_name;
		ULONG len = utf_16to8(&curve_name, curves->pEccCurveNames[i]);
		jstring c_name = (*env)->NewStringUTF(env, curve_name);
		(*env)->CallBooleanMethod(env, result, hash_set_add, c_name);
		free(curve_name);
	}

	free(curves);

	BCryptCloseAlgorithmProvider(handle, 0);
	return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_keysizeSupported(JNIEnv *env,
                                                                                                                           jobject self,
                                                                                                                           jint keysize) {
	switch (keysize) {
		case 256:
		case 384:
		case 521:
			return JNI_TRUE;
		default:
			return JNI_FALSE;
	}
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_paramsSupported(JNIEnv *env,
                                                                                                                          jobject self,
                                                                                                                          jobject params) {
	if (params == NULL) {
		return JNI_FALSE;
	}

	if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
		jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
		jstring name = (*env)->CallObjectMethod(env, params, get_name);
		const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
		const named_curve_t *curve = lookup_curve(utf_name);
		(*env)->ReleaseStringUTFChars(env, name, utf_name);
		return curve == NULL ? JNI_FALSE : JNI_TRUE;
	} else if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
		jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
		jobject curve = (*env)->CallObjectMethod(env, params, get_curve);

		jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
		jobject field = (*env)->CallObjectMethod(env, curve, get_field);

		if ((*env)->IsInstanceOf(env, field, fp_field_class)) {
			return JNI_TRUE;
		} else {
			return JNI_FALSE;
		}
	} else {
		return JNI_FALSE;
	}
}

static jobject bytes_to_biginteger(JNIEnv *env, PBYTE bytes, int len) {
	jmethodID biginteger_init = (*env)->GetMethodID(env, biginteger_class, "<init>", "(I[B)V");
	jbyteArray byte_array = (*env)->NewByteArray(env, len);
	jbyte *data = (*env)->GetByteArrayElements(env, byte_array, NULL);
	memcpy(data, bytes, len);
	(*env)->ReleaseByteArrayElements(env, byte_array, data, 0);
	jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, byte_array);
	return result;
}

static void biginteger_to_bytes(JNIEnv *env, jobject bigint, PBYTE bytes, ULONG len) {
	jmethodID to_byte_array = (*env)->GetMethodID(env, biginteger_class, "toByteArray", "()[B");

	jbyteArray byte_array = (jbyteArray)(*env)->CallObjectMethod(env, bigint, to_byte_array);
	jsize byte_length = (*env)->GetArrayLength(env, byte_array);
	jbyte *byte_data = (*env)->GetByteArrayElements(env, byte_array, NULL);
	memcpy(bytes, &byte_data[byte_length - len], len);
	(*env)->ReleaseByteArrayElements(env, byte_array, byte_data, JNI_ABORT);
}

static jobject create_ec_param_spec(JNIEnv *env, PBYTE eccParams, PULONG paramLength) {
	//
	//     BCRYPT_ECCFULLKEY_BLOB   header
	//     P[cbFieldLength]              Prime specifying the base field.
	//     A[cbFieldLength]              Coefficient A of the equation y^2 = x^3 + A*x + B mod p
	//     B[cbFieldLength]              Coefficient B of the equation y^2 = x^3 + A*x + B mod p
	//     Gx[cbFieldLength]             X-coordinate of the base point.
	//     Gy[cbFieldLength]             Y-coordinate of the base point.
	//     n[cbSubgroupOrder]            Order of the group generated by G = (x,y)
	//     h[cbCofactor]                 Cofactor of G in E.
	//     S[cbSeed]                     Seed of the curve.

	BCRYPT_ECCFULLKEY_BLOB *header = (BCRYPT_ECCFULLKEY_BLOB *)eccParams;
	PBYTE paramsStart = &eccParams[sizeof(BCRYPT_ECCFULLKEY_BLOB)];

	// cbFieldLength
	PBYTE P = paramsStart;
	PBYTE A = P + header->cbFieldLength;
	PBYTE B = A + header->cbFieldLength;
	PBYTE GX = B + header->cbFieldLength;
	PBYTE GY = GX + header->cbFieldLength;

	// cbSubgroupOrder
	PBYTE N = GY + header->cbFieldLength;

	// cbCofactor
	PBYTE H = N + header->cbSubgroupOrder;

	// cbSeed
	PBYTE S = H + header->cbCofactor;

	*paramLength =
	    sizeof(BCRYPT_ECCFULLKEY_BLOB) + 5 * header->cbFieldLength + header->cbSubgroupOrder + header->cbCofactor + header->cbSeed;

	jobject p_int = bytes_to_biginteger(env, P, header->cbFieldLength);

	jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
	jobject field = (*env)->NewObject(env, fp_field_class, fp_field_init, p_int);

	jobject a_int = bytes_to_biginteger(env, A, header->cbFieldLength);
	jobject b_int = bytes_to_biginteger(env, B, header->cbFieldLength);

	jmethodID elliptic_curve_init = (*env)->GetMethodID(env, elliptic_curve_class, "<init>",
	                                                    "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
	jobject elliptic_curve = (*env)->NewObject(env, elliptic_curve_class, elliptic_curve_init, field, a_int, b_int);

	jobject gx_int = bytes_to_biginteger(env, GX, header->cbFieldLength);
	jobject gy_int = bytes_to_biginteger(env, GY, header->cbFieldLength);

	jmethodID point_init = (*env)->GetMethodID(env, point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
	jobject g = (*env)->NewObject(env, point_class, point_init, gx_int, gy_int);

	jobject n_int = bytes_to_biginteger(env, N, header->cbSubgroupOrder);

	jobject h_int = bytes_to_biginteger(env, H, header->cbCofactor);
	jmethodID bigint_to_int = (*env)->GetMethodID(env, biginteger_class, "intValue", "()I");
	jint cof = (*env)->CallIntMethod(env, h_int, bigint_to_int);

	jmethodID ec_parameter_spec_init = (*env)->GetMethodID(
	    env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
	return (*env)->NewObject(env, ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, n_int, cof);
}

static ULONG create_curve(JNIEnv *env, jobject params, PBYTE *curve) {
	jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
	jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

	jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
	jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

	jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
	jint bits = (*env)->CallIntMethod(env, field, get_bits);
	jint bytes = (bits + 7) / 8;

	jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
	jobject a = (*env)->CallObjectMethod(env, elliptic_curve, get_a);

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

	jmethodID get_h = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCofactor", "()I");
	jint h = (*env)->CallIntMethod(env, params, get_h);

	jmethodID get_bitlength = (*env)->GetMethodID(env, biginteger_class, "bitLength", "()I");
	jint order_bits = (*env)->CallIntMethod(env, n, get_bitlength);
	jint order_bytes = (order_bits + 7) / 8;

	// header_size + 5*bytes + order_bytes + cof_size + 0
	ULONG bufSize = sizeof(BCRYPT_ECC_PARAMETER_HEADER) + 5 * bytes + order_bytes + 1 + 0;
	*curve = calloc(bufSize, 1);
	BCRYPT_ECC_PARAMETER_HEADER *header = (BCRYPT_ECC_PARAMETER_HEADER *)*curve;
	header->dwVersion = 1;
	header->dwCurveType = 1;  // 1 -> Prime short Weierstrass, 2 -> Prime Twisted Edwards, 3 -> Montgomery
	header->dwCurveGenerationAlgId = 0;
	header->cbFieldLength = bytes;
	header->cbSubgroupOrder = order_bytes;
	header->cbCofactor = 1;
	header->cbSeed = 0;

	PBYTE paramsStart = &(*curve)[sizeof(BCRYPT_ECC_PARAMETER_HEADER)];

	biginteger_to_bytes(env, p, paramsStart, bytes);
	biginteger_to_bytes(env, a, paramsStart + bytes, bytes);
	biginteger_to_bytes(env, b, paramsStart + 2 * bytes, bytes);
	biginteger_to_bytes(env, gx, paramsStart + 3 * bytes, bytes);
	biginteger_to_bytes(env, gy, paramsStart + 4 * bytes, bytes);
	biginteger_to_bytes(env, n, paramsStart + 5 * bytes, order_bytes);
	PBYTE cof_ptr = (PBYTE)(paramsStart + 5 * bytes + order_bytes);
	*cof_ptr = (BYTE)h;
	return bufSize;
}

static ULONG init_algo(JNIEnv *env, BCRYPT_ALG_HANDLE *handle, jint *keyflag, NWPSTR *curve_name, LPCWSTR algo, jobject params) {
	NTSTATUS status;
	if (NT_FAILURE(status = BCryptOpenAlgorithmProvider(handle, algo, MS_PRIMITIVE_PROVIDER, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		return 0;
	}
	ULONG result = 0;
	if ((*env)->IsInstanceOf(env, params, ecgen_parameter_spec_class)) {
		jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
		jstring name = (*env)->CallObjectMethod(env, params, get_name);
		jint utf_length = (*env)->GetStringUTFLength(env, name);
		PUCHAR chars = calloc(utf_length + 1, 1);
		(*env)->GetStringUTFRegion(env, name, 0, utf_length, chars);
		const named_curve_t *curve = lookup_curve(chars);
		ULONG ret = utf_8to16(curve_name, chars);
		if (NT_FAILURE(status = BCryptSetProperty(*handle, BCRYPT_ECC_CURVE_NAME, (PUCHAR)*curve_name, ret * sizeof(WCHAR), 0))) {
			wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
			return 0;
		}
		free(chars);
		result = curve->bits;
		*keyflag = KEYFLAG_IMPLICIT;
	} else if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
		PBYTE curve;
		ULONG curveLen = create_curve(env, params, &curve);
		if (NT_FAILURE(status = BCryptSetProperty(*handle, BCRYPT_ECC_PARAMETERS, curve, curveLen, 0))) {
			wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
			return 0;
		}
		free(curve);

		jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
		jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

		jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
		jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

		jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
		jint bits = (*env)->CallIntMethod(env, field, get_bits);
		result = bits;
		*keyflag = KEYFLAG_EXPLICIT;
		*curve_name = NULL;
	}
	return result;
}

static jobject key_to_privkey(JNIEnv *env, BCRYPT_KEY_HANDLE key, jint flag, LPCWSTR curve) {
	NTSTATUS status;
	ULONG bufSize = 0;
	if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCFULLPRIVATE_BLOB, NULL, 0, &bufSize, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptExportKey(full, length only)\n", status);
		return NULL;
	}
	if (bufSize == 0) {
		printf("buf 0\n");
		return NULL;
	}

	PBYTE fullBuf = calloc(bufSize, 1);
	if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCFULLPRIVATE_BLOB, fullBuf, bufSize, &bufSize, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptExportKey(full, whole)\n", status);
		free(fullBuf);
		return NULL;
	}

	ULONG paramLength;
	jobject ec_priv_param_spec = create_ec_param_spec(env, fullBuf, &paramLength);

	// fullBuf looks like:
	//     BCRYPT_ECCFULLKEY_BLOB   header
	//     P[cbFieldLength]              Prime specifying the base field.
	//     A[cbFieldLength]              Coefficient A of the equation y^2 = x^3 + A*x + B mod p
	//     B[cbFieldLength]              Coefficient B of the equation y^2 = x^3 + A*x + B mod p
	//     Gx[cbFieldLength]             X-coordinate of the base point.
	//     Gy[cbFieldLength]             Y-coordinate of the base point.
	//     n[cbSubgroupOrder]            Order of the group generated by G = (x,y)
	//     h[cbCofactor]                 Cofactor of G in E.
	//     S[cbSeed]                     Seed of the curve.
	//     Qx[cbFieldLength]             X-coordinate of the public point.
	//     Qy[cbFieldLength]             Y-coordinate of the public point.
	//     d[cbSubgroupOrder]            Private key.
	BCRYPT_ECCFULLKEY_BLOB *privHeader = (BCRYPT_ECCFULLKEY_BLOB *)fullBuf;
	PBYTE priv_x = &fullBuf[paramLength];
	PBYTE priv_y = priv_x + privHeader->cbFieldLength;
	PBYTE priv = priv_y + privHeader->cbFieldLength;

	jbyteArray meta_bytes = NULL;
	jbyteArray header_bytes = NULL;
	switch (flag) {
		case 0: {
			// meta = curve
			jint meta_len = (wcslen(curve) + 1) * sizeof(WCHAR);
			meta_bytes = (*env)->NewByteArray(env, meta_len);
			jbyte *meta_data = (*env)->GetByteArrayElements(env, meta_bytes, NULL);
			memcpy(meta_data, curve, meta_len);
			(*env)->ReleaseByteArrayElements(env, meta_bytes, meta_data, 0);
		}
		case 1:
		case 2: {
			// meta = null
			// header = full
			header_bytes = (*env)->NewByteArray(env, paramLength);
			jbyte *header_data = (*env)->GetByteArrayElements(env, header_bytes, NULL);
			memcpy(header_data, fullBuf, paramLength);
			(*env)->ReleaseByteArrayElements(env, header_bytes, header_data, 0);
			break;
		}
		default:
			// header = small
			if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &bufSize, 0))) {
				wprintf(L"**** Error 0x%x returned by BCryptExportKey(small, length only)\n", status);
				free(fullBuf);
				return NULL;
			}
			if (bufSize == 0) {
				printf("buf 0\n");
				free(fullBuf);
				return NULL;
			}
			PBYTE smallBuf = calloc(bufSize, 1);
			if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, smallBuf, bufSize, &bufSize, 0))) {
				wprintf(L"**** Error 0x%x returned by BCryptExportKey(small, whole)\n", status);
				free(fullBuf);
				free(smallBuf);
				return NULL;
			}
			// smallBuf looks like:
			//	   BCRYPT_ECCKEY_BLOB header
			//     Qx[cbFieldLength]             X-coordinate of the public point.
			//     Qy[cbFieldLength]             Y-coordinate of the public point.
			//     d[cbSubgroupOrder]            Private key.
			header_bytes = (*env)->NewByteArray(env, sizeof(BCRYPT_ECCKEY_BLOB));
			jbyte *header_data = (*env)->GetByteArrayElements(env, header_bytes, NULL);
			memcpy(header_data, smallBuf, sizeof(BCRYPT_ECCKEY_BLOB));
			(*env)->ReleaseByteArrayElements(env, header_bytes, header_data, 0);
			free(smallBuf);
			break;
	}

	jbyteArray x_bytes = (*env)->NewByteArray(env, privHeader->cbFieldLength);
	jbyte *x_data = (*env)->GetByteArrayElements(env, x_bytes, NULL);
	memcpy(x_data, priv_x, privHeader->cbFieldLength);
	(*env)->ReleaseByteArrayElements(env, x_bytes, x_data, 0);

	jbyteArray y_bytes = (*env)->NewByteArray(env, privHeader->cbFieldLength);
	jbyte *y_data = (*env)->GetByteArrayElements(env, y_bytes, NULL);
	memcpy(y_data, priv_y, privHeader->cbFieldLength);
	(*env)->ReleaseByteArrayElements(env, y_bytes, y_data, 0);

	jbyteArray priv_bytes = (*env)->NewByteArray(env, privHeader->cbSubgroupOrder);
	jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
	memcpy(key_priv, priv, privHeader->cbSubgroupOrder);
	(*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

	free(fullBuf);

	jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "(I[B[B[B[B[BLjava/security/spec/ECParameterSpec;)V");
	return (*env)->NewObject(env, privkey_class, ec_priv_init, flag, meta_bytes, header_bytes, x_bytes, y_bytes, priv_bytes,
	                         ec_priv_param_spec);
}

static jobject key_to_pubkey(JNIEnv *env, BCRYPT_KEY_HANDLE key, jint flag, LPCWSTR curve) {
	NTSTATUS status;
	ULONG bufSize = 0;
	if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, NULL, 0, &bufSize, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptExportKey(full, length only)\n", status);
		return NULL;
	}
	if (bufSize == 0) {
		printf("err0\n");
		return NULL;
	}

	PBYTE fullBuf = calloc(bufSize, 1);
	if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, fullBuf, bufSize, &bufSize, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptExportKey(full, whole)\n", status);
		return NULL;
	}

	ULONG paramLength;
	jobject ec_pub_param_spec = create_ec_param_spec(env, fullBuf, &paramLength);

	// fullBuf looks like:
	//     BCRYPT_ECCFULLKEY_BLOB   header
	//     P[cbFieldLength]              Prime specifying the base field.
	//     A[cbFieldLength]              Coefficient A of the equation y^2 = x^3 + A*x + B mod p
	//     B[cbFieldLength]              Coefficient B of the equation y^2 = x^3 + A*x + B mod p
	//     Gx[cbFieldLength]             X-coordinate of the base point.
	//     Gy[cbFieldLength]             Y-coordinate of the base point.
	//     n[cbSubgroupOrder]            Order of the group generated by G = (x,y)
	//     h[cbCofactor]                 Cofactor of G in E.
	//     S[cbSeed]                     Seed of the curve.
	//     Qx[cbFieldLength]			 X-coordinate of the public point.
	//     Qy[cbFieldLength]			 Y-coordinate of the public point.
	BCRYPT_ECCFULLKEY_BLOB *pubHeader = (BCRYPT_ECCFULLKEY_BLOB *)fullBuf;
	PBYTE pub_x = &fullBuf[paramLength];
	PBYTE pub_y = pub_x + pubHeader->cbFieldLength;

	jbyteArray meta_bytes = NULL;
	jbyteArray header_bytes = NULL;
	switch (flag) {
		case 0: {
			// meta = curve
			jint meta_len = (wcslen(curve) + 1) * sizeof(WCHAR);
			meta_bytes = (*env)->NewByteArray(env, meta_len);
			jbyte *meta_data = (*env)->GetByteArrayElements(env, meta_bytes, NULL);
			memcpy(meta_data, curve, meta_len);
			(*env)->ReleaseByteArrayElements(env, meta_bytes, meta_data, 0);
		}
		case 1:
		case 2: {
			header_bytes = (*env)->NewByteArray(env, paramLength);
			jbyte *header_data = (*env)->GetByteArrayElements(env, header_bytes, NULL);
			memcpy(header_data, pubHeader, paramLength);
			(*env)->ReleaseByteArrayElements(env, header_bytes, header_data, 0);
			break;
		}
		default:
			// header = small
			if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &bufSize, 0))) {
				wprintf(L"**** Error 0x%x returned by BCryptExportKey(small, length only)\n", status);
				free(fullBuf);
				return NULL;
			}
			if (bufSize == 0) {
				printf("buf 0\n");
				free(fullBuf);
				return NULL;
			}
			PBYTE smallBuf = calloc(bufSize, 1);
			if (NT_FAILURE(status = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, smallBuf, bufSize, &bufSize, 0))) {
				wprintf(L"**** Error 0x%x returned by BCryptExportKey(small, whole)\n", status);
				free(fullBuf);
				free(smallBuf);
				return NULL;
			}
			// smallBuf looks like:
			//	   BCRYPT_ECCKEY_BLOB header
			//     Qx[cbFieldLength]             X-coordinate of the public point.
			//     Qy[cbFieldLength]             Y-coordinate of the public point.
			header_bytes = (*env)->NewByteArray(env, sizeof(BCRYPT_ECCKEY_BLOB));
			jbyte *header_data = (*env)->GetByteArrayElements(env, header_bytes, NULL);
			memcpy(header_data, smallBuf, sizeof(BCRYPT_ECCKEY_BLOB));
			(*env)->ReleaseByteArrayElements(env, header_bytes, header_data, 0);
			free(smallBuf);
			break;
	}

	jbyteArray x_bytes = (*env)->NewByteArray(env, pubHeader->cbFieldLength);
	jbyte *x_data = (*env)->GetByteArrayElements(env, x_bytes, NULL);
	memcpy(x_data, pub_x, pubHeader->cbFieldLength);
	(*env)->ReleaseByteArrayElements(env, x_bytes, x_data, 0);

	jbyteArray y_bytes = (*env)->NewByteArray(env, pubHeader->cbFieldLength);
	jbyte *y_data = (*env)->GetByteArrayElements(env, y_bytes, NULL);
	memcpy(y_data, pub_y, pubHeader->cbFieldLength);
	(*env)->ReleaseByteArrayElements(env, y_bytes, y_data, 0);

	free(fullBuf);

	jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "(I[B[B[B[BLjava/security/spec/ECParameterSpec;)V");
	return (*env)->NewObject(env, pubkey_class, ec_pub_init, flag, meta_bytes, header_bytes, x_bytes, y_bytes, ec_pub_param_spec);
}

JNIEXPORT jobject JNICALL
Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_generate__ILjava_security_SecureRandom_2(JNIEnv *env,
                                                                                                                        jobject self,
                                                                                                                        jint keysize,
                                                                                                                        jobject random) {
	NTSTATUS status;
	BCRYPT_ALG_HANDLE handle = NULL;

	jclass mscng_kpg_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeKeyPairGeneratorSpi$Mscng");
	jfieldID type_id = (*env)->GetFieldID(env, mscng_kpg_class, "type", "Ljava/lang/String;");
	jstring type = (jstring)(*env)->GetObjectField(env, self, type_id);
	const char *type_data = (*env)->GetStringUTFChars(env, type, NULL);
	LPCWSTR algo;
	if (strcmp(type_data, "ECDH") == 0) {
		switch (keysize) {
			case 256:
				algo = BCRYPT_ECDH_P256_ALGORITHM;
				break;
			case 384:
				algo = BCRYPT_ECDH_P384_ALGORITHM;
				break;
			case 521:
				algo = BCRYPT_ECDH_P521_ALGORITHM;
				break;
			default:
				// unreachable
				return NULL;
		}
	} else if (strcmp(type_data, "ECDSA") == 0) {
		switch (keysize) {
			case 256:
				algo = BCRYPT_ECDSA_P256_ALGORITHM;
				break;
			case 384:
				algo = BCRYPT_ECDSA_P384_ALGORITHM;
				break;
			case 521:
				algo = BCRYPT_ECDSA_P521_ALGORITHM;
				break;
			default:
				// unreachable
				return NULL;
		}
	} else {
		// unreachable
		return NULL;
	}
	(*env)->ReleaseStringUTFChars(env, type, type_data);

	if (NT_FAILURE(status = BCryptOpenAlgorithmProvider(&handle, algo, MS_PRIMITIVE_PROVIDER, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptOpenAlgorithmProvider", status);
		return NULL;
	}

	BCRYPT_KEY_HANDLE key = NULL;

	native_timing_start();
	status = BCryptGenerateKeyPair(handle, &key, keysize, 0);
	native_timing_pause();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptGenerateKeyPair\n", status);
		BCryptCloseAlgorithmProvider(handle, 0);
		return NULL;
	}

	native_timing_restart();
	status = BCryptFinalizeKeyPair(key, 0);
	native_timing_stop();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptFinalizeKeyPair\n", status);
		BCryptCloseAlgorithmProvider(handle, 0);
		return NULL;
	}

	jobject privkey = key_to_privkey(env, key, KEYFLAG_NIST, NULL);
	jobject pubkey = key_to_pubkey(env, key, KEYFLAG_NIST, NULL);

	jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

	BCryptDestroyKey(key);
	BCryptCloseAlgorithmProvider(handle, 0);
	return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jobject JNICALL
Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(
    JNIEnv *env, jobject self, jobject params, jobject random) {
	NTSTATUS status;
	BCRYPT_ALG_HANDLE handle = NULL;
	BCRYPT_KEY_HANDLE key = NULL;

	jclass mscng_kpg_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeKeyPairGeneratorSpi$Mscng");
	jfieldID type_id = (*env)->GetFieldID(env, mscng_kpg_class, "type", "Ljava/lang/String;");
	jstring type = (jstring)(*env)->GetObjectField(env, self, type_id);
	const char *type_data = (*env)->GetStringUTFChars(env, type, NULL);
	LPCWSTR algo;
	if (strcmp(type_data, "ECDH") == 0) {
		algo = BCRYPT_ECDH_ALGORITHM;
	} else if (strcmp(type_data, "ECDSA") == 0) {
		algo = BCRYPT_ECDSA_ALGORITHM;
	} else {
		// unreachable
		return NULL;
	}
	(*env)->ReleaseStringUTFChars(env, type, type_data);

	jint keyflag;
	NWPSTR curveName;
	ULONG bits = init_algo(env, &handle, &keyflag, &curveName, algo, params);
	if (bits == 0) {
		throw_new(env, "java/security/GeneralSecurityException", "Couldn't initialize algo.");
		return NULL;
	}

	native_timing_start();
	status = BCryptGenerateKeyPair(handle, &key, bits, 0);
	native_timing_pause();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptGenerateKeyPair\n", status);
		BCryptCloseAlgorithmProvider(handle, 0);
		return NULL;
	}

	native_timing_restart();
	status = BCryptFinalizeKeyPair(key, 0);
	native_timing_stop();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptFinalizeKeyPair\n", status);
		BCryptCloseAlgorithmProvider(handle, 0);
		return NULL;
	}

	jobject privkey = key_to_privkey(env, key, keyflag, curveName);
	jobject pubkey = key_to_pubkey(env, key, keyflag, curveName);

	if (curveName) {
		free(curveName);
	}

	jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

	BCryptDestroyKey(key);
	BCryptCloseAlgorithmProvider(handle, 0);
	return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

static NTSTATUS init_use_algo(JNIEnv *env, BCRYPT_ALG_HANDLE *handle, LPCWSTR type, jint keyflag, jbyteArray meta, jobject params) {
	LPCWSTR ecdh_algos[] = {BCRYPT_ECDH_ALGORITHM, BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_P384_ALGORITHM, BCRYPT_ECDH_P521_ALGORITHM};
	LPCWSTR ecdsa_algos[] = {BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM};

	LPCWSTR *algos;
	LPCWSTR algo;
	if (lstrcmpW(type, BCRYPT_ECDH_ALGORITHM) == 0) {
		algos = ecdh_algos;
	} else if (lstrcmpW(type, BCRYPT_ECDSA_ALGORITHM) == 0) {
		algos = ecdsa_algos;
	} else {
		// unreachable
		return STATUS_INVALID_PARAMETER;
	}

	switch (keyflag) {
		case KEYFLAG_IMPLICIT:
		case KEYFLAG_EXPLICIT:
		case KEYFLAG_OTHER:
			algo = algos[0];
			break;
		case KEYFLAG_NIST: {
			jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
			jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

			jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
			jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

			jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
			jint bits = (*env)->CallIntMethod(env, field, get_bits);
			switch (bits) {
				case 256:
					algo = algos[1];
					break;
				case 384:
					algo = algos[2];
					break;
				case 521:
					algo = algos[3];
					break;
				default:
					return STATUS_INVALID_PARAMETER;
			}
			break;
		}
	}
	NTSTATUS status;

	if (NT_FAILURE(status = BCryptOpenAlgorithmProvider(handle, algo, MS_PRIMITIVE_PROVIDER, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		return status;
	}

	switch (keyflag) {
		case KEYFLAG_IMPLICIT: {
			jint meta_len = (*env)->GetArrayLength(env, meta);
			jbyte *meta_data = (*env)->GetByteArrayElements(env, meta, NULL);
			// if (NT_FAILURE(status = BCryptSetProperty(*handle, BCRYPT_ECC_CURVE_NAME, meta_data, meta_len, 0))) {
			//	throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptSetProperty(curve name)\n",
			//status);
			//	(*env)->ReleaseByteArrayElements(env, meta, meta_data, JNI_ABORT);
			//	return status;
			//}
			(*env)->ReleaseByteArrayElements(env, meta, meta_data, JNI_ABORT);
			break;
		}
		case KEYFLAG_EXPLICIT:
		case KEYFLAG_OTHER: {
			PBYTE curve;
			ULONG curve_len = create_curve(env, params, &curve);
			if (NT_FAILURE(status = BCryptSetProperty(*handle, BCRYPT_ECC_PARAMETERS, curve, curve_len, 0))) {
				throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptSetProperty(parameters)\n",
				              status);
				free(curve);
				return status;
			}
			free(curve);
			break;
		}
	}
	return STATUS_SUCCESS;
}

static jint get_keyflag(JNIEnv *env, jobject key) {
	if ((*env)->IsInstanceOf(env, key, pubkey_class) || (*env)->IsInstanceOf(env, key, privkey_class)) {
		jclass key_class = (*env)->GetObjectClass(env, key);
		jmethodID get_flag = (*env)->GetMethodID(env, key_class, "getFlag", "()I");
		return (*env)->CallIntMethod(env, key, get_flag);
	} else {
		return KEYFLAG_OTHER;
	}
}

static jbyteArray get_meta(JNIEnv *env, jobject key) {
	if ((*env)->IsInstanceOf(env, key, pubkey_class) || (*env)->IsInstanceOf(env, key, privkey_class)) {
		jclass key_class = (*env)->GetObjectClass(env, key);
		jmethodID get_meta = (*env)->GetMethodID(env, key_class, "getMeta", "()[B");
		return (jbyteArray)(*env)->CallObjectMethod(env, key, get_meta);
	} else {
		return NULL;
	}
}

JNIEXPORT jbyteArray JNICALL
Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Mscng_generateSecret__Ljava_security_interfaces_ECPublicKey_2Ljava_security_interfaces_ECPrivateKey_2Ljava_security_spec_AlgorithmParameterSpec_2(
    JNIEnv *env, jobject self, jobject pubkey, jobject privkey, jobject params) {
	NTSTATUS status;

	jclass mscng_ka_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeKeyAgreementSpi$Mscng");
	jfieldID type_id = (*env)->GetFieldID(env, mscng_ka_class, "type", "Ljava/lang/String;");
	jstring type = (jstring)(*env)->GetObjectField(env, self, type_id);
	const char *type_data = (*env)->GetStringUTFChars(env, type, NULL);
	LPCWSTR kdf_algo;
	if (strcmp(type_data, "ECDHwithSHA1KDF(CNG)") == 0) {
		kdf_algo = BCRYPT_SHA1_ALGORITHM;
	} else if (strcmp(type_data, "ECDHwithSHA256KDF(CNG)") == 0) {
		kdf_algo = BCRYPT_SHA256_ALGORITHM;
	} else if (strcmp(type_data, "ECDHwithSHA384KDF(CNG)") == 0) {
		kdf_algo = BCRYPT_SHA384_ALGORITHM;
	} else if (strcmp(type_data, "ECDHwithSHA512KDF(CNG)") == 0) {
		kdf_algo = BCRYPT_SHA512_ALGORITHM;
	} else {
		// unreachable
		return NULL;
	}
	(*env)->ReleaseStringUTFChars(env, type, type_data);

	BCRYPT_ALG_HANDLE kaHandle = NULL;

	jint pub_flag = get_keyflag(env, pubkey);
	if (pub_flag == KEYFLAG_OTHER) {
		throw_new(env, "java/security/InvalidAlgorithmParameterException", "Cannot import non-native public key.");
		return NULL;
	}
	jbyteArray meta = get_meta(env, pubkey);

	if (NT_FAILURE(status = init_use_algo(env, &kaHandle, BCRYPT_ECDH_ALGORITHM, pub_flag, meta, params))) {
		return NULL;
	}

	BCRYPT_KEY_HANDLE pkey = NULL;
	BCRYPT_KEY_HANDLE skey = NULL;

	jmethodID get_data_priv = (*env)->GetMethodID(env, pubkey_class, "getData", "()[B");
	jbyteArray pubkey_barray = (jbyteArray)(*env)->CallObjectMethod(env, pubkey, get_data_priv);

	jint pub_length = (*env)->GetArrayLength(env, pubkey_barray);
	jbyte *pub_data = (*env)->GetByteArrayElements(env, pubkey_barray, NULL);
	if (NT_FAILURE(status = BCryptImportKeyPair(kaHandle, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, &pkey, pub_data, pub_length, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptImportKeyPair(pub)\n", status);
		BCryptCloseAlgorithmProvider(kaHandle, 0);
		(*env)->ReleaseByteArrayElements(env, pubkey_barray, pub_data, JNI_ABORT);
		return NULL;
	}
	(*env)->ReleaseByteArrayElements(env, pubkey_barray, pub_data, JNI_ABORT);

	jint priv_flag = get_keyflag(env, privkey);
	if (priv_flag == KEYFLAG_OTHER) {
		throw_new(env, "java/security/InvalidAlgorithmParameterException", "Cannot import non-native private key.");
		return NULL;
	}

	jmethodID get_data_pub = (*env)->GetMethodID(env, privkey_class, "getData", "()[B");
	jbyteArray privkey_barray = (jbyteArray)(*env)->CallObjectMethod(env, privkey, get_data_pub);

	jint priv_length = (*env)->GetArrayLength(env, privkey_barray);
	jbyte *priv_data = (*env)->GetByteArrayElements(env, privkey_barray, NULL);
	if (NT_FAILURE(status = BCryptImportKeyPair(kaHandle, NULL, BCRYPT_ECCFULLPRIVATE_BLOB, &skey, priv_data, priv_length, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptImportKeyPair(priv)\n", status);
		BCryptCloseAlgorithmProvider(kaHandle, 0);
		BCryptDestroyKey(pkey);
		(*env)->ReleaseByteArrayElements(env, privkey_barray, priv_data, JNI_ABORT);
		return NULL;
	}
	(*env)->ReleaseByteArrayElements(env, privkey_barray, priv_data, JNI_ABORT);

	BCRYPT_SECRET_HANDLE ka = NULL;

	native_timing_start();
	status = BCryptSecretAgreement(skey, pkey, &ka, 0);
	native_timing_stop();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptSecretAgreement\n", status);
		BCryptCloseAlgorithmProvider(kaHandle, 0);
		BCryptDestroyKey(pkey);
		BCryptDestroyKey(skey);
		return NULL;
	}

	BCryptBufferDesc paramList = {0};
	BCryptBuffer kdfParams[1] = {0};
	kdfParams[0].BufferType = KDF_HASH_ALGORITHM;
	kdfParams[0].cbBuffer = (DWORD)((wcslen(kdf_algo) + 1) * sizeof(WCHAR));
	kdfParams[0].pvBuffer = (PVOID)kdf_algo;
	paramList.cBuffers = 1;
	paramList.pBuffers = kdfParams;
	paramList.ulVersion = BCRYPTBUFFER_VERSION;

	ULONG bufSize = 0;
	if (NT_FAILURE(status = BCryptDeriveKey(ka, BCRYPT_KDF_HASH, &paramList, NULL, 0, &bufSize, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptDeriveKey(length only)\n", status);
		return NULL;
	}

	PBYTE derived = calloc(bufSize, 1);
	if (NT_FAILURE(status = BCryptDeriveKey(ka, BCRYPT_KDF_HASH, &paramList, derived, bufSize, &bufSize, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptDeriveKey(whole)\n", status);
		return NULL;
	}

	jbyteArray result = (*env)->NewByteArray(env, bufSize);
	jbyte *result_data = (*env)->GetByteArrayElements(env, result, NULL);
	memcpy(result_data, derived, bufSize);
	(*env)->ReleaseByteArrayElements(env, result, result_data, 0);

	free(derived);
	BCryptDestroyKey(pkey);
	BCryptDestroyKey(skey);
	BCryptDestroySecret(ka);
	BCryptCloseAlgorithmProvider(kaHandle, 0);
	return result;
}

JNIEXPORT jobject JNICALL
Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Mscng_generateSecret__Ljava_security_interfaces_ECPublicKey_2Ljava_security_interfaces_ECPrivateKey_2Ljava_security_spec_AlgorithmParameterSpec_2Ljava_lang_String_2(
    JNIEnv *env, jobject self, jobject pubkey, jobject privkey, jobject params, jstring algorithm) {
	throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
	return NULL;
}

static LPCWSTR get_sighash_algo(JNIEnv *env, jobject self) {
	jclass mscng_sig_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeSignatureSpi$Mscng");
	jfieldID type_id = (*env)->GetFieldID(env, mscng_sig_class, "type", "Ljava/lang/String;");
	jstring type = (jstring)(*env)->GetObjectField(env, self, type_id);
	const char *type_data = (*env)->GetStringUTFChars(env, type, NULL);
	LPCWSTR hash_algo;
	if (strcmp(type_data, "SHA1withECDSA") == 0) {
		hash_algo = BCRYPT_SHA1_ALGORITHM;
	} else if (strcmp(type_data, "SHA256withECDSA") == 0) {
		hash_algo = BCRYPT_SHA256_ALGORITHM;
	} else if (strcmp(type_data, "SHA384withECDSA") == 0) {
		hash_algo = BCRYPT_SHA384_ALGORITHM;
	} else if (strcmp(type_data, "SHA512withECDSA") == 0) {
		hash_algo = BCRYPT_SHA512_ALGORITHM;
	} else {
		// unreachable
		return NULL;
	}
	(*env)->ReleaseStringUTFChars(env, type, type_data);
	return hash_algo;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Mscng_sign(JNIEnv *env, jobject self,
                                                                                                          jbyteArray data, jobject privkey,
                                                                                                          jobject params) {
	NTSTATUS status;
	LPCWSTR hash_algo = get_sighash_algo(env, self);

	BCRYPT_ALG_HANDLE sigHandle = NULL;

	jint keyflag = get_keyflag(env, privkey);
	if (keyflag == KEYFLAG_OTHER) {
		throw_new(env, "java/security/InvalidAlgorithmParameterException", "Cannot import non-native private key.");
		return NULL;
	}
	jbyteArray meta = get_meta(env, privkey);

	if (NT_FAILURE(status = init_use_algo(env, &sigHandle, BCRYPT_ECDSA_ALGORITHM, keyflag, meta, params))) {
		return NULL;
	}

	if (NT_FAILURE(status = BCryptOpenAlgorithmProvider(&sigHandle, BCRYPT_ECDSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		return NULL;
	}

	BCRYPT_ALG_HANDLE hashHandle = NULL;

	if (NT_FAILURE(status = BCryptOpenAlgorithmProvider(&hashHandle, hash_algo, NULL, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		return NULL;
	}

	DWORD dummy = 0;
	DWORD hash_len = 0;
	if (NT_FAILURE(status = BCryptGetProperty(hashHandle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_len, sizeof(DWORD), &dummy, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptGetProperty(hash len)\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		return NULL;
	}

	PBYTE hash = calloc(hash_len, 1);

	jint data_len = (*env)->GetArrayLength(env, data);
	jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
	native_timing_start();
	status = BCryptHash(hashHandle, NULL, 0, data_bytes, data_len, hash, hash_len);
	native_timing_pause();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptHash\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		free(hash);
		(*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
		return NULL;
	}
	(*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

	BCRYPT_KEY_HANDLE skey = NULL;

	jmethodID get_data = (*env)->GetMethodID(env, privkey_class, "getData", "()[B");
	jbyteArray privkey_barray = (jbyteArray)(*env)->CallObjectMethod(env, privkey, get_data);

	jint priv_length = (*env)->GetArrayLength(env, privkey_barray);
	jbyte *priv_data = (*env)->GetByteArrayElements(env, privkey_barray, NULL);
	if (NT_FAILURE(status = BCryptImportKeyPair(sigHandle, NULL, BCRYPT_ECCFULLPRIVATE_BLOB, &skey, priv_data, priv_length, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptImportKeyPair\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		free(hash);
		(*env)->ReleaseByteArrayElements(env, privkey_barray, priv_data, JNI_ABORT);
		return NULL;
	}
	(*env)->ReleaseByteArrayElements(env, privkey_barray, priv_data, JNI_ABORT);

	DWORD sig_len = 0;
	native_timing_restart();
	status = BCryptSignHash(skey, NULL, hash, hash_len, NULL, 0, &sig_len, 0);
	native_timing_pause();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptSignHash(len only)\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		free(hash);
		return NULL;
	}

	PBYTE sig_buf = calloc(sig_len, 1);

	native_timing_restart();
	status = BCryptSignHash(skey, NULL, hash, hash_len, sig_buf, sig_len, &sig_len, 0);
	native_timing_stop();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptSignHash(do)\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		free(hash);
		free(sig_buf);
		return NULL;
	}

	DWORD half_len = sig_len / 2;
	jobject sig = asn1_der_encode(env, sig_buf, half_len, sig_buf + half_len, half_len);

	free(hash);
	free(sig_buf);
	BCryptDestroyKey(skey);
	BCryptCloseAlgorithmProvider(hashHandle, 0);
	BCryptCloseAlgorithmProvider(sigHandle, 0);

	return sig;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Mscng_verify(JNIEnv *env, jobject self,
                                                                                                          jbyteArray sig, jbyteArray data,
                                                                                                          jobject pubkey, jobject params) {
	NTSTATUS status;
	LPCWSTR hash_algo = get_sighash_algo(env, self);

	BCRYPT_ALG_HANDLE sigHandle = NULL;

	jint keyflag = get_keyflag(env, pubkey);
	if (keyflag == KEYFLAG_OTHER) {  // TODO: This is not necessary
		throw_new(env, "java/security/InvalidAlgorithmParameterException", "Cannot import non-native public key.");
		return JNI_FALSE;
	}
	jbyteArray meta = get_meta(env, pubkey);

	if (NT_FAILURE(status = init_use_algo(env, &sigHandle, BCRYPT_ECDSA_ALGORITHM, keyflag, meta, params))) {
		return JNI_FALSE;
	}

	BCRYPT_ALG_HANDLE hashHandle = NULL;

	if (NT_FAILURE(status = BCryptOpenAlgorithmProvider(&hashHandle, hash_algo, NULL, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		return JNI_FALSE;
	}

	DWORD dummy = 0;
	DWORD hash_len = 0;
	if (NT_FAILURE(status = BCryptGetProperty(hashHandle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_len, sizeof(DWORD), &dummy, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptGetProperty(hash len)\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		return JNI_FALSE;
	}

	PBYTE hash = calloc(hash_len, 1);

	jint data_len = (*env)->GetArrayLength(env, data);
	jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
	native_timing_start();
	status = BCryptHash(hashHandle, NULL, 0, data_bytes, data_len, hash, hash_len);
	native_timing_pause();

	if (NT_FAILURE(status)) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptHash\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		free(hash);
		(*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
		return JNI_FALSE;
	}
	(*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

	BCRYPT_KEY_HANDLE pkey = NULL;

	jmethodID get_data = (*env)->GetMethodID(env, pubkey_class, "getData", "()[B");
	jbyteArray pubkey_barray = (jbyteArray)(*env)->CallObjectMethod(env, pubkey, get_data);

	jint pub_length = (*env)->GetArrayLength(env, pubkey_barray);
	jbyte *pub_data = (*env)->GetByteArrayElements(env, pubkey_barray, NULL);
	if (NT_FAILURE(status = BCryptImportKeyPair(sigHandle, NULL, BCRYPT_ECCFULLPUBLIC_BLOB, &pkey, pub_data, pub_length, 0))) {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptImportKeyPair\n", status);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		free(hash);
		(*env)->ReleaseByteArrayElements(env, pubkey_barray, pub_data, JNI_ABORT);
		return JNI_FALSE;
	}
	(*env)->ReleaseByteArrayElements(env, pubkey_barray, pub_data, JNI_ABORT);
    
    jmethodID get_n = (*env)->GetMethodID(env, ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
    jobject n = (*env)->CallObjectMethod(env, params, get_n);
    jmethodID get_bitlength = (*env)->GetMethodID(env, biginteger_class, "bitLength", "()I");
	jint ord_bits = (*env)->CallIntMethod(env, n, get_bitlength);
	jint ord_bytes = (ord_bits + 7) / 8;

	jint sig_len = (*env)->GetArrayLength(env, sig);
	jbyte *sig_data = (*env)->GetByteArrayElements(env, sig, NULL);
	jbyte *r;
	size_t rlen;
	jbyte *s;
	size_t slen;
	bool decode = asn1_der_decode(env, sig, &r, &rlen, &s, &slen);
	(*env)->ReleaseByteArrayElements(env, sig, sig_data, JNI_ABORT);

	if (!decode) {
		throw_new(env, "java/security/GeneralSecurityException", "Error decoding sig.");
		BCryptDestroyKey(pkey);
		BCryptCloseAlgorithmProvider(sigHandle, 0);
		BCryptCloseAlgorithmProvider(hashHandle, 0);
		free(hash);
		return JNI_FALSE;
	}

	jbyte *r_cpy = r;
	jbyte *s_cpy = s;
    if (rlen > ord_bytes) {
        r_cpy += ord_bytes - rlen;
    }
    if (slen > ord_bytes) {
        s_cpy += ord_bytes - slen;
    }
    if (rlen < ord_bytes) {
        r_cpy = _alloca(ord_bytes);
        memset(r_cpy, 0, ord_bytes);
        memcpy(r_cpy, r + (ord_bytes - rlen), ord_bytes);
    }
    if (slen < ord_bytes) {
        s_cpy = _alloca(ord_bytes);
        memset(s_cpy, 0, ord_bytes);
        memcpy(s_cpy, s + (ord_bytes - slen), ord_bytes);
    }
    rlen = ord_bytes;
    slen = ord_bytes;

	UCHAR *sig_full = calloc(rlen + slen, 1);
	memcpy(sig_full, r_cpy, rlen);
	memcpy(sig_full + rlen, s_cpy, slen);
	free(r);
	free(s);

	native_timing_restart();
	NTSTATUS result = BCryptVerifySignature(pkey, NULL, hash, hash_len, sig_full, rlen + slen, 0);
	native_timing_stop();

	free(hash);
	free(sig_full);
	BCryptDestroyKey(pkey);
	BCryptCloseAlgorithmProvider(hashHandle, 0);
	BCryptCloseAlgorithmProvider(sigHandle, 0);

	if (result == STATUS_SUCCESS) {
		return JNI_TRUE;
	} else if (result == STATUS_INVALID_SIGNATURE) {
		return JNI_FALSE;
	} else {
		throw_new_var(env, "java/security/GeneralSecurityException", "Error 0x%x returned by BCryptVerifySignature\n", status);
		return JNI_FALSE;
	}
}