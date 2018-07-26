#include "native.h"
#include <windows.h>
#include <bcrypt.h>

#include "c_utils.h"

static jclass provider_class;

#define NT_SUCCESS(status)          (((NTSTATUS)(status)) >= 0)
#define NT_FAILURE(status)          !NT_SUCCESS(status)

#define STATUS_SUCCESS 0x00000000
#define STATUS_INVALID_SIGNATURE 0xC000A000

typedef struct {
	ULONG                   dwVersion;              //Version of the structure
	ECC_CURVE_TYPE_ENUM     dwCurveType;            //Supported curve types.
	ECC_CURVE_ALG_ID_ENUM   dwCurveGenerationAlgId; //For X.592 verification purposes, if we include Seed we will need to include the algorithm ID.
	ULONG                   cbFieldLength;          //Byte length of the fields P, A, B, X, Y.
	ULONG                   cbSubgroupOrder;        //Byte length of the subgroup.
	ULONG                   cbCofactor;             //Byte length of cofactor of G in E.
	ULONG                   cbSeed;                 //Byte length of the seed used to generate the curve.
} BCRYPT_ECC_PARAMETER_HEADER;

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MscngLib_createProvider(JNIEnv *env, jobject self){
    jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$Mscng");
    provider_class = (*env)->NewGlobalRef(env, local_provider_class);

    jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    jstring name =  (*env)->NewStringUTF(env, "Microsoft CNG");
    double version = 1.0;
    return (*env)->NewObject(env, provider_class, init, name, version, name);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Mscng_setup(JNIEnv *env, jobject self) {
    INIT_PROVIDER(env, provider_class);

    ADD_KPG(env, self, "ECDH", "MscngECDH");
    ADD_KPG(env, self, "ECDSA", "MscngECDSA");

    ADD_KA(env, self, "ECDHwithSHA1KDF", "MscngECDHwithSHA1KDF");
    ADD_KA(env, self, "ECDHwithSHA256KDF", "MscngECDHwithSHA256KDF");
    ADD_KA(env, self, "ECDHwithSHA384KDF", "MscngECDHwithSHA384KDF");
    ADD_KA(env, self, "ECDHwithSHA512KDF", "MscngECDHwithSHA512KDF");

    ADD_SIG(env, self, "SHA1withECDSA", "MscngECDSAwithSHA1");
    ADD_SIG(env, self, "SHA256withECDSA", "MscngECDSAwithSHA256");
    ADD_SIG(env, self, "SHA384withECDSA", "MscngECDSAwithSHA384");
    ADD_SIG(env, self, "SHA512withECDSA", "MscngECDSAwithSHA112");

    init_classes(env, "Mscng");
}

typedef struct {
    const char *name;
    ULONG bits;
} named_curve_t;

static named_curve_t named_curves[] = {
    {"curve25519", 256},
    {"brainpoolP160r1", 160},
    {"brainpoolP160t1", 160},
    {"brainpoolP192r1", 192},
    {"brainpoolP192t1", 192},
    {"brainpoolP224r1", 224},
    {"brainpoolP224t1", 224},
    {"brainpoolP256r1", 256},
    {"brainpoolP256t1", 256},
    {"brainpoolP320r1", 320},
    {"brainpoolP320t1", 320},
    {"brainpoolP384r1", 384},
    {"brainpoolP384t1", 384},
    {"brainpoolP512r1", 512},
    {"brainpoolP512t1", 512},
    {"ec192wapi", 192},
    {"nistP192", 192},
    {"nistP224", 224},
    {"nistP256", 256},
    {"nistP384", 384},
    {"nistP521", 521},
    {"numsP256t1", 256},
    {"numsP384t1", 384},
    {"numsP512t1", 512},
    {"secP160k1", 160},
    {"secP160r1", 160},
    {"secP160r2", 160},
    {"secP192k1", 192},
    {"secP192r1", 192},
    {"secP224k1", 224},
    {"secP224r1", 224},
    {"secP256k1", 256},
    {"secP256r1", 256},
    {"secP384r1", 384},
    {"secP521r1", 521},
    {"wtls12", 224},
    {"wtls7", 160},
    {"wtls9", 160},
    {"x962P192v1", 192},
    {"x962P192v2", 192},
    {"x962P192v3", 192},
    {"x962P239v1", 239},
    {"x962P239v2", 239},
    {"x962P239v3", 239},
    {"x962P256v1", 256}
};

static const named_curve_t* lookup_curve(const char *name) {
    for (size_t i = 0; i < sizeof(named_curves)/sizeof(named_curve_t); ++i) {
        if (strcmp(name, named_curves[i].name) == 0) {
            return &named_curves[i];
        }
    }
    return NULL;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_MscngLib_getCurves(JNIEnv *env, jobject self) {
    jclass hash_set_class = (*env)->FindClass(env, "java/util/TreeSet");

    jmethodID hash_set_ctr = (*env)->GetMethodID(env, hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = (*env)->GetMethodID(env, hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = (*env)->NewObject(env, hash_set_class, hash_set_ctr);

    for (size_t i = 0; i < sizeof(named_curves)/sizeof(named_curve_t); ++i) {
        jstring curve_name = (*env)->NewStringUTF(env, named_curves[i].name);
        (*env)->CallBooleanMethod(env, result, hash_set_add, curve_name);
    }
    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_keysizeSupported(JNIEnv *env, jobject self, jint keysize) {
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_paramsSupported(JNIEnv *env, jobject self, jobject params) {
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

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random) {
    throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
    return NULL;
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

    jbyteArray byte_array = (jbyteArray) (*env)->CallObjectMethod(env, bigint, to_byte_array);
    jsize byte_length = (*env)->GetArrayLength(env, byte_array);
    jbyte *byte_data = (*env)->GetByteArrayElements(env, byte_array, NULL);
    memcpy(bytes, &byte_data[byte_length - len], len);
    (*env)->ReleaseByteArrayElements(env, byte_array, byte_data, JNI_ABORT);
}

static jobject create_ec_param_spec(JNIEnv *env, PBYTE eccParams, ULONG paramLength) {
    // Taken from https://github.com/dotnet/corefx, thanks! This API is nowhere to be found.
    //
    //     BCRYPT_ECC_PARAMETER_HEADER  header
    //     byte[cbFieldLength]          P
    //     byte[cbFieldLength]          A
    //     byte[cbFieldLength]          B
    //     byte[cbFieldLength]          G.X
    //     byte[cbFieldLength]          G.Y
    //     byte[cbSubgroupOrder]        Order (n)
    //     byte[cbCofactor]             Cofactor (h)
    //     byte[cbSeed]                 Seed

    //    BCRYPT_ECC_PARAMETER_HEADER
    //        internal int Version;              //Version of the structure
    //        internal ECC_CURVE_TYPE_ENUM CurveType;            //Supported curve types.
    //        internal ECC_CURVE_ALG_ID_ENUM CurveGenerationAlgId; //For X.592 verification purposes, if we include Seed we will need to include the algorithm ID.
    //        internal int cbFieldLength;          //Byte length of the fields P, A, B, X, Y.
    //        internal int cbSubgroupOrder;        //Byte length of the subgroup.
    //        internal int cbCofactor;             //Byte length of cofactor of G in E.
    //        internal int cbSeed;                 //Byte length of the seed used to generate the curve.

    //    internal enum ECC_CURVE_TYPE_ENUM : int
    //        {
    //            BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE = 0x1,
    //            BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE = 0x2,
    //            BCRYPT_ECC_PRIME_MONTGOMERY_CURVE = 0x3,
    //        }

    //    internal enum ECC_CURVE_ALG_ID_ENUM : int
    //        {
    //            BCRYPT_NO_CURVE_GENERATION_ALG_ID = 0x0,
    //        }
    BCRYPT_ECC_PARAMETER_HEADER *header = (BCRYPT_ECC_PARAMETER_HEADER*)eccParams;
    PBYTE paramsStart = &eccParams[sizeof(BCRYPT_ECC_PARAMETER_HEADER)];

    //cbFieldLength
    PBYTE P = paramsStart;
    PBYTE A = P + header->cbFieldLength;
    PBYTE B = A + header->cbFieldLength;
    PBYTE GX = B + header->cbFieldLength;
    PBYTE GY = GX + header->cbFieldLength;

    //cbSubgroupOrder
    PBYTE N = GY + header->cbFieldLength;

    //cbCofactor
    PBYTE H = N + header->cbSubgroupOrder;

    //cbSeed
    PBYTE S = H + header->cbCofactor;

    jobject p_int = bytes_to_biginteger(env, P, header->cbFieldLength);

    jmethodID fp_field_init = (*env)->GetMethodID(env, fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject field = (*env)->NewObject(env, fp_field_class, fp_field_init, p_int);

    jobject a_int = bytes_to_biginteger(env, A, header->cbFieldLength);
    jobject b_int = bytes_to_biginteger(env, B, header->cbFieldLength);

    jmethodID elliptic_curve_init = (*env)->GetMethodID(env, elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = (*env)->NewObject(env, elliptic_curve_class, elliptic_curve_init, field, a_int, b_int);

    jobject gx_int = bytes_to_biginteger(env, GX, header->cbFieldLength);
    jobject gy_int = bytes_to_biginteger(env, GY, header->cbFieldLength);

    jmethodID point_init = (*env)->GetMethodID(env, point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject g = (*env)->NewObject(env, point_class, point_init, gx_int, gy_int);

    jobject n_int = bytes_to_biginteger(env, N, header->cbSubgroupOrder);

    jobject h_int = bytes_to_biginteger(env, H, header->cbCofactor);
    jmethodID bigint_to_int = (*env)->GetMethodID(env, biginteger_class, "intValue", "()I");
    jint cof = (*env)->CallIntMethod(env, h_int, bigint_to_int);

    jmethodID ec_parameter_spec_init = (*env)->GetMethodID(env, ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
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

    jmethodID get_a = (*env)->GetMethodID(env, elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
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
    ULONG bufSize = sizeof(BCRYPT_ECC_PARAMETER_HEADER) + 5*bytes + order_bytes + sizeof(jint) + 0;
    *curve = calloc(bufSize, 1);
    BCRYPT_ECC_PARAMETER_HEADER *header = (BCRYPT_ECC_PARAMETER_HEADER*)*curve;
    header->dwVersion = 1;
    header->dwCurveType = 1; //1 -> Prime short Weierstrass, 2 -> Prime Twisted Edwards, 3 -> Montgomery
    header->dwCurveGenerationAlgId = 0;
    header->cbFieldLength = bytes;
    header->cbSubgroupOrder = order_bytes;
    header->cbCofactor = sizeof(jint);
    header->cbSeed = 0;

    PBYTE paramsStart = &(*curve)[sizeof(BCRYPT_ECC_PARAMETER_HEADER)];

    biginteger_to_bytes(env, p, paramsStart, bytes);
    biginteger_to_bytes(env, a, paramsStart + bytes, bytes);
    biginteger_to_bytes(env, b, paramsStart + 2*bytes, bytes);
    biginteger_to_bytes(env, gx, paramsStart + 3*bytes, bytes);
    biginteger_to_bytes(env, gy, paramsStart + 4*bytes, bytes);
    biginteger_to_bytes(env, n, paramsStart + 5*bytes, order_bytes);
    jint *cof_ptr = (jint *) (paramsStart + 5*bytes + order_bytes);
    *cof_ptr = h;
    return bufSize;
}

static ULONG init_algo(JNIEnv *env, BCRYPT_ALG_HANDLE *handle, LPCWSTR algo, jobject params) {
    if (NT_FAILURE(BCryptOpenAlgorithmProvider(handle, algo, MS_PRIMITIVE_PROVIDER, 0))) {
        //err
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
        if (NT_FAILURE(BCryptSetProperty(*handle, BCRYPT_ECC_CURVE_NAME, chars, strlen(chars), 0))) {
            //err
            return 0;
        }
		free(chars);
		result = curve->bits;
    } else if ((*env)->IsInstanceOf(env, params, ec_parameter_spec_class)) {
        PBYTE curve;
        ULONG curveLen = create_curve(env, params, &curve);
        if (NT_FAILURE(BCryptSetProperty(*handle, BCRYPT_ECC_PARAMETERS, curve, curveLen, 0))) {
            //err
            return 0;
        }
        free(curve);

		jmethodID get_curve = (*env)->GetMethodID(env, ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
		jobject elliptic_curve = (*env)->CallObjectMethod(env, params, get_curve);

		jmethodID get_field = (*env)->GetMethodID(env, elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
		jobject field = (*env)->CallObjectMethod(env, elliptic_curve, get_field);

		jmethodID get_bits = (*env)->GetMethodID(env, fp_field_class, "getFieldSize", "()I");
		jint bits = (*env)->CallIntMethod(env, field, get_bits);
		result = (bits + 7) / 8;
    }
    return result;
}

static jobject key_to_privkey(JNIEnv *env, BCRYPT_KEY_HANDLE key, jobject ec_param_spec) {
    ULONG bufSize = 0;
    if (NT_FAILURE(BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &bufSize, 0))) {
        //err
    }
    if (bufSize == 0) {
        //err
    }

	PBYTE privBuf = calloc(bufSize, 1);
    if (NT_FAILURE(BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, privBuf, bufSize, &bufSize, 0))) {
        //err
    }

    // privBuf looks like:
    //     BCRYPT_ECCKEY_BLOB   header
    //     byte[cbKey]          Q.X
    //     byte[cbKey]          Q.Y
    //     byte[cbKey]          D
    BCRYPT_ECCKEY_BLOB *privHeader = (BCRYPT_ECCKEY_BLOB*)privBuf;
    PBYTE priv_x = &privBuf[sizeof(BCRYPT_ECCKEY_BLOB)];
    PBYTE priv_y = priv_x + privHeader->cbKey;
    PBYTE priv = priv_y + privHeader->cbKey;

    jbyteArray header_bytes = (*env)->NewByteArray(env, sizeof(BCRYPT_ECCKEY_BLOB));
    jbyte *header_data = (*env)->GetByteArrayElements(env, header_bytes, NULL);
    memcpy(header_data, privHeader, sizeof(BCRYPT_ECCKEY_BLOB));
    (*env)->ReleaseByteArrayElements(env, header_bytes, header_data, 0);
    
    jbyteArray x_bytes = (*env)->NewByteArray(env, privHeader->cbKey);
    jbyte *x_data = (*env)->GetByteArrayElements(env, x_bytes, NULL);
    memcpy(x_data, priv_x, privHeader->cbKey);
    (*env)->ReleaseByteArrayElements(env, x_bytes, x_data, 0);

    jbyteArray y_bytes = (*env)->NewByteArray(env, privHeader->cbKey);
    jbyte *y_data = (*env)->GetByteArrayElements(env, y_bytes, NULL);
    memcpy(y_data, priv_y, privHeader->cbKey);
    (*env)->ReleaseByteArrayElements(env, y_bytes, y_data, 0);

    jbyteArray priv_bytes = (*env)->NewByteArray(env, privHeader->cbKey);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
    memcpy(key_priv, priv, privHeader->cbKey);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

	free(privBuf);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([B[BLjava/security/spec/ECParameterSpec;)V");
    return (*env)->NewObject(env, privkey_class, ec_priv_init, header_bytes, x_bytes, y_bytes, priv_bytes, ec_priv_param_spec);
}

static jobject key_to_pubkey(JNIEnv *env, BCRYPT_KEY_HANDLE key, jobject ec_param_spec) {
    ULONG bufSize = 0;
    if (NT_FAILURE(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &bufSize, 0))) {
        //err
    }

	PBYTE pubBuf = calloc(bufSize, 1);
    if (NT_FAILURE(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, pubBuf, bufSize, &bufSize, 0))) {
        //err
    }

    // pubBuf looks like:
    //     BCRYPT_ECCKEY_BLOB   header
    //     byte[cbKey]          Q.X
    //     byte[cbKey]          Q.Y
    BCRYPT_ECCKEY_BLOB *pubHeader = (BCRYPT_ECCKEY_BLOB*)pubBuf;
    PBYTE pub_x = &pubBuf[sizeof(BCRYPT_ECCKEY_BLOB)];
    PBYTE pub_y = pub_x + pubHeader->cbKey;

    jbyteArray header_bytes = (*env)->NewByteArray(env, sizeof(BCRYPT_ECCKEY_BLOB));
    jbyte *header_data = (*env)->GetByteArrayElements(env, header_bytes, NULL);
    memcpy(header_data, pubHeader, sizeof(BCRYPT_ECCKEY_BLOB));
    (*env)->ReleaseByteArrayElements(env, header_bytes, header_data, 0);

    jbyteArray x_bytes = (*env)->NewByteArray(env, pubHeader->cbKey);
    jbyte *x_data = (*env)->GetByteArrayElements(env, x_bytes, NULL);
    memcpy(x_data, pub_x, pubHeader->cbKey);
    (*env)->ReleaseByteArrayElements(env, x_bytes, x_data, 0);

    jbyteArray y_bytes = (*env)->NewByteArray(env, pubHeader->cbKey);
    jbyte *y_data = (*env)->GetByteArrayElements(env, y_bytes, NULL);
    memcpy(y_data, pub_y, pubHeader->cbKey);
    (*env)->ReleaseByteArrayElements(env, y_bytes, y_data, 0);

	free(pubBuf);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([B[B[BLjava/security/spec/ECParameterSpec;)V");
    return (*env)->NewObject(env, pubkey_class, ec_pub_init, header_bytes, x_bytes, y_bytes, ec_pub_param_spec);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random){
    BCRYPT_ALG_HANDLE kaHandle = NULL;
    BCRYPT_KEY_HANDLE key = NULL;

    jclass mscng_kpg_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeKeyPairGeneratorSpi$Mscng");
    jfieldID type_id = (*env)->GetFieldID(env, mscng_kpg_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) (*env)->GetObjectField(env, self, type_id);
    const char* type_data = (*env)->GetStringUTFChars(env, type, NULL);
    LPCWSTR algo;
    if (strcmp(type_data, "ECDH") == 0) {
        algo = BCRYPT_ECDH_ALGORITHM;
    } else if (strcmp(type_data, "ECDSA") == 0) {
        algo = BCRYPT_ECDSA_ALGORITHM;
    } else {
        //err
    }
    (*env)->ReleaseStringUTFChars(env, type, type_data);

	ULONG bits = init_algo(env, &kaHandle, algo, params);
    if (bits == 0) {
        //err
    }

    ULONG paramsSize;
    if (NT_FAILURE(BCryptGetProperty(kaHandle, BCRYPT_ECC_PARAMETERS, NULL, 0, &paramsSize, 0))) {
        //err
    }
    if (paramsSize == 0) {
        //err
    }

	PBYTE eccParams = calloc(paramsSize, 1);
    if (NT_FAILURE(BCryptGetProperty(kaHandle, BCRYPT_ECC_PARAMETERS, eccParams, paramsSize, &paramsSize, 0))) {
        //err
    }

    jobject ec_param_spec = create_ec_param_spec(env, eccParams, paramsSize);

	free(eccParams);

    if (NT_FAILURE(BCryptGenerateKeyPair(kaHandle, &key, bits, 0))) {
        //err
    }

    if (NT_FAILURE(BCryptFinalizeKeyPair(key, 0))) {
        //err
    }

    jobject privkey = key_to_privkey(env, key, ec_param_spec);
    jobject pubkey = key_to_pubkey(env, key, ec_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(kaHandle, 0);
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Mscng_generateSecret(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params) {
    jclass mscng_ka_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeKeyAgreementSpi$Mscng");
    jfieldID type_id = (*env)->GetFieldID(env, mscng_ka_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) (*env)->GetObjectField(env, self, type_id);
    const char* type_data = (*env)->GetStringUTFChars(env, type, NULL);
    LPCWSTR kdf_algo;
    if (strcmp(type_data, "ECDHwithSHA1KDF") == 0) {
        kdf_algo = BCRYPT_SHA1_ALGORITHM;
    } else if (strcmp(type_data, "ECDHwithSHA256KDF") == 0) {
        kdf_algo = BCRYPT_SHA256_ALGORITHM;
    } else if (strcmp(type_data, "ECDHwithSHA384KDF") == 0) {
        kdf_algo = BCRYPT_SHA384_ALGORITHM;
    } else if (strcmp(type_data, "ECDHwithSHA512KDF") == 0) {
        kdf_algo = BCRYPT_SHA512_ALGORITHM;
    } else {
        //err
    }
    (*env)->ReleaseStringUTFChars(env, type, type_data);

    BCRYPT_ALG_HANDLE kaHandle = NULL;

    if (!init_algo(env, &kaHandle, BCRYPT_ECDH_ALGORITHM, params)) {
        //err
    }

    BCRYPT_KEY_HANDLE pkey = NULL;
    BCRYPT_KEY_HANDLE skey = NULL;

    jint pub_length = (*env)->GetArrayLength(env, pubkey);
    jbyte *pub_data = (*env)->GetByteArrayElements(env, pubkey, NULL);
    if (NT_FAILURE(BCryptImportKeyPair(kaHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, &pkey, pub_data, pub_length, 0))) {
        //err
    }
    (*env)->ReleaseByteArrayElements(env, pubkey, pub_data, JNI_ABORT);

    jint priv_length = (*env)->GetArrayLength(env, privkey);
    jbyte *priv_data = (*env)->GetByteArrayElements(env, privkey, NULL);
    if (NT_FAILURE(BCryptImportKeyPair(kaHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, &skey, priv_data, priv_length, 0))) {
        //err
    }
    (*env)->ReleaseByteArrayElements(env, privkey, priv_data, JNI_ABORT);

    BCRYPT_SECRET_HANDLE ka = NULL;

    if (NT_FAILURE(BCryptSecretAgreement(skey, pkey, &ka, 0))) {
        //err
    }

    BCryptBufferDesc paramList = {0};
    BCryptBuffer kdfParams[1] = {0};
    kdfParams[0].BufferType = KDF_HASH_ALGORITHM;
    kdfParams[0].cbBuffer = (DWORD)((wcslen(kdf_algo) + 1) * sizeof(WCHAR));
    kdfParams[0].pvBuffer = (PVOID)kdf_algo;
    paramList.cBuffers = 1;
    paramList.pBuffers = kdfParams;
    paramList.ulVersion = BCRYPTBUFFER_VERSION;

    //TODO: Is this the actual KDF-1 or KDF-2 algo or something completely different? *This does not use the counter!!!*
    ULONG bufSize = 0;
    if (NT_FAILURE(BCryptDeriveKey(ka, BCRYPT_KDF_HASH, &paramList, NULL, 0, &bufSize, 0))) {
        //err
    }

	PBYTE derived = calloc(bufSize, 1);
    if (NT_FAILURE(BCryptDeriveKey(ka, BCRYPT_KDF_HASH, &paramList, derived, bufSize, &bufSize, 0))) {
        //err
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

static LPCWSTR get_sighash_algo(JNIEnv *env, jobject self) {
    jclass mscng_sig_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeSignatureSpi$Mscng");
    jfieldID type_id = (*env)->GetFieldID(env, mscng_sig_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) (*env)->GetObjectField(env, self, type_id);
    const char* type_data = (*env)->GetStringUTFChars(env, type, NULL);
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
        //err
    }
    (*env)->ReleaseStringUTFChars(env, type, type_data);
    return hash_algo;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Mscng_sign(JNIEnv *env, jobject self, jbyteArray data, jbyteArray privkey, jobject params) {
    LPCWSTR hash_algo = get_sighash_algo(env, self);

    BCRYPT_ALG_HANDLE sigHandle = NULL;

    if (!init_algo(env, &sigHandle, BCRYPT_ECDSA_ALGORITHM, params)) {
        //err
    }

    BCRYPT_ALG_HANDLE hashHandle = NULL;

    if (NT_FAILURE(BCryptOpenAlgorithmProvider(&hashHandle, hash_algo, NULL, 0))) {
        //err
    }

    DWORD dummy = 0;
    DWORD hash_len = 0;
    if (NT_FAILURE(BCryptGetProperty(hashHandle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_len, sizeof(DWORD), &dummy, 0))) {
        //err
    }

	PBYTE hash = calloc(hash_len, 1);

    jint data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (NT_FAILURE(BCryptHash(hashHandle, NULL, 0, data_bytes, data_len, hash, hash_len))) {
        //err
    }
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    BCRYPT_KEY_HANDLE skey = NULL;

    jint priv_length = (*env)->GetArrayLength(env, privkey);
    jbyte *priv_data = (*env)->GetByteArrayElements(env, privkey, NULL);
    if (NT_FAILURE(BCryptImportKeyPair(sigHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, &skey, priv_data, priv_length, 0))) {
        //err
    }
    (*env)->ReleaseByteArrayElements(env, privkey, priv_data, JNI_ABORT);

    DWORD sig_len = 0;
    if (NT_FAILURE(BCryptSignHash(skey, NULL, hash, hash_len, NULL, 0, &sig_len, 0))) {
        //err
    }

    jbyteArray sig = (*env)->NewByteArray(env, sig_len);
    jbyte *sig_data = (*env)->GetByteArrayElements(env, sig, NULL);
    if (NT_FAILURE(BCryptSignHash(skey, NULL, hash, hash_len, sig_data, sig_len, &sig_len, 0))) {
        //err
    }
    (*env)->ReleaseByteArrayElements(env, sig, sig_data, 0);

	free(hash);

    BCryptDestroyKey(skey);
    BCryptCloseAlgorithmProvider(hashHandle, 0);
    BCryptCloseAlgorithmProvider(sigHandle, 0);

    return sig;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Mscng_verify(JNIEnv *env, jobject self, jbyteArray sig, jbyteArray data, jbyteArray pubkey, jobject params) {
    LPCWSTR hash_algo = get_sighash_algo(env, self);

    BCRYPT_ALG_HANDLE sigHandle = NULL;

    if (!init_algo(env, &sigHandle, BCRYPT_ECDSA_ALGORITHM, params)) {
        //err
    }

    BCRYPT_ALG_HANDLE hashHandle = NULL;

    if (NT_FAILURE(BCryptOpenAlgorithmProvider(&hashHandle, hash_algo, NULL, 0))) {
        //err
    }

    DWORD dummy = 0;
    DWORD hash_len = 0;
    if (NT_FAILURE(BCryptGetProperty(hashHandle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_len, sizeof(DWORD), &dummy, 0))) {
        //err
    }

	PBYTE hash = calloc(hash_len, 1);

    jint data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (NT_FAILURE(BCryptHash(hashHandle, NULL, 0, data_bytes, data_len, hash, hash_len))) {
        //err
    }
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    BCRYPT_KEY_HANDLE pkey = NULL;

    jint pub_length = (*env)->GetArrayLength(env, pubkey);
    jbyte *pub_data = (*env)->GetByteArrayElements(env, pubkey, NULL);
    if (NT_FAILURE(BCryptImportKeyPair(sigHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, &pkey, pub_data, pub_length, 0))) {
        //err
    }
    (*env)->ReleaseByteArrayElements(env, pubkey, pub_data, JNI_ABORT);

    jint sig_len = (*env)->GetArrayLength(env, sig);
    jbyte *sig_data = (*env)->GetByteArrayElements(env, sig, NULL);
    NTSTATUS result = BCryptVerifySignature(pkey, NULL, hash, hash_len, sig_data, sig_len, 0);
    (*env)->ReleaseByteArrayElements(env, sig, sig_data, JNI_ABORT);

	free(hash);

    BCryptDestroyKey(pkey);
    BCryptCloseAlgorithmProvider(hashHandle, 0);
    BCryptCloseAlgorithmProvider(sigHandle, 0);

    if (result == STATUS_SUCCESS) {
        return JNI_TRUE;
    } else if (result == STATUS_INVALID_SIGNATURE) {
        return JNI_FALSE;
    } else {
        //err
        return JNI_FALSE;
    }
}