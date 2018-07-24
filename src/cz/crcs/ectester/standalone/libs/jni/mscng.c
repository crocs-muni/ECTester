#include "native.h"
#include <windows.h>
#include <bcrypt.h>

#include "c_utils.h"

static jclass provider_class;

#define NT_SUCCESS(status)          (((NTSTATUS)(status)) >= 0)
#define NT_FAILURE(status)          !NT_SUCCESS(status)

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
        if (strcasecmp(name, named_curves[i].name) == 0) {
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
    jbyteArray bytes = (*env)->NewByteArray(env, len);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
    memcpy(data, bytes, len);
    (*env)->ReleaseByteArrayElements(env, bytes, data, 0);
    jobject result = (*env)->NewObject(env, biginteger_class, biginteger_init, 1, bytes);
    return result;
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
    PBYTE A = p + header->cbFieldLength;
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

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Mscng_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random){
    BCRYPT_ALG_HANDLE kaHandle = NULL;
    BCRYPT_KEY_HANDLE key = NULL;

    //TODO: CUSTOM curve with BCRYPT_ECC_PARAMETERS??

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

    if (NT_FAILURE(BCryptOpenAlgorithmProvider(&kaHandle, algo, MS_PRIMITIVE_PROVIDER, 0))) {
        //err
    }

    jmethodID get_name = (*env)->GetMethodID(env, ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
    jstring name = (*env)->CallObjectMethod(env, params, get_name);
    const char *utf_name = (*env)->GetStringUTFChars(env, name, NULL);
    const named_curve_t *curve = lookup_curve(utf_name);
    if (NT_FAILURE(BCryptSetProperty(kaHandle, BCRYPT_ECC_CURVE_NAME, utf_name, strlen(utf_name), 0))) {
        //err
    }
    (*env)->ReleaseStringUTFChars(env, name, utf_name);

    ULONG paramsSize;
    if (NT_FAILURE(BCryptGetProperty(kaHandle, BCRYPT_ECC_PARAMETERS, NULL, 0, &paramsSize, 0))) {
        //err
    }
    if (paramsSize == 0) {
        //TODO: what now?
    }

    BYTE params[paramsSize];
    if (NT_FAILURE(BCryptGetProperty(kaHandle, BCRYPT_ECC_PARAMETERS, params, paramsSize, &paramsSize, 0))) {
        //err
    }

    jobject ec_param_spec = create_ec_param_spec(env, params, paramsSize);

    if (NT_FAILURE(BCryptGenerateKeyPair(kaHandle, &key, curve.bits, 0)) {
        //err
    }

    if (NT_FAILURE(BCryptFinalizeKeyPair(key, 0))) {
        //err
    }

    ULONG bufSize;
    if (NT_FAILURE(BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &bufSize, 0))) {
        //err
    }

    BYTE privBuf[bufSize];
    if (NT_FAILURE(BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, privBuf, bufsize, &bufSize, 0))) {
        //err
    }

    // privBuf looks like:
    //     BCRYPT_ECCKEY_BLOB   header
    //     byte[cbKey]          Q.X
    //     byte[cbKey]          Q.Y
    //     byte[cbKey]          D
    BCRYPT_ECCKEY_BLOB *header = (BCRYPT_ECCKEY_BLOB*)privBuf;
    PBYTE x = &privBuf[sizeof(BCRYPT_ECCKEY_BLOB)];
    PBYTE y = x + header->cbKey;
    PBYTE priv = y + header->cbKey;

    jbyteArray priv_bytes = (*env)->NewByteArray(env, header->cbKey);
    jbyte *key_priv = (*env)->GetByteArrayElements(env, priv_bytes, NULL);
    memcpy(key_priv, priv, header->cbKey);
    (*env)->ReleaseByteArrayElements(env, priv_bytes, key_priv, 0);

    jobject ec_priv_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_priv_init = (*env)->GetMethodID(env, privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = (*env)->NewObject(env, privkey_class, ec_priv_init, priv_bytes, ec_priv_param_spec);

    jbyteArray x_bytes = (*env)->NewByteArray(env, header->cbKey);
    jbyte *x_data = (*env)->GetByteArrayElements(env, x_bytes, NULL);
    memcpy(x_data, x, header->cbKey);
    (*env)->ReleaseByteArrayElements(env, x_bytes, x_data, 0);
    jbyteArray y_bytes = (*env)->NewByteArray(env, header->cbKey);
    jbyte *y_data = (*env)->GetByteArrayElements(env, y_bytes, NULL);
    memcpy(y_data, y, header->cbKey);
    (*env)->ReleaseByteArrayElements(env, y_bytes, y_data, 0);

    jobject ec_pub_param_spec = (*env)->NewLocalRef(env, ec_param_spec);
    jmethodID ec_pub_init = (*env)->GetMethodID(env, pubkey_class, "<init>", "([B[BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = (*env)->NewObject(env, pubkey_class, ec_pub_init, x_bytes, y_bytes, ec_pub_param_spec);

    jmethodID keypair_init = (*env)->GetMethodID(env, keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(kaHandle, 0);
    return (*env)->NewObject(env, keypair_class, keypair_init, pubkey, privkey);
}