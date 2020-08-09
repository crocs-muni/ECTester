#include "native.h"
#include <string>

#include <botan/version.h>
#include <botan/rng.h>
#include <botan/secmem.h>
#include <botan/auto_rng.h>

#include <botan/ec_group.h>
#include <botan/ecc_key.h>
#include <botan/ecdsa.h>
#include <botan/eckcdsa.h>
#include <botan/ecgdsa.h>
#include <botan/ecdh.h>
#include <botan/pubkey.h>
#include "cpp_utils.hpp"
#include "c_timing.h"

static jclass provider_class;
static Botan::AutoSeeded_RNG rng;

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_BotanLib_createProvider(JNIEnv *env, jobject self) {
    /* Create the custom provider. */
    jclass local_provider_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeProvider$Botan");
    provider_class = (jclass) env->NewGlobalRef(local_provider_class);

    jmethodID init = env->GetMethodID(local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    const char* info_str = Botan::version_cstr();
    const char* v_str = Botan::short_version_cstr();
    std::string name_str = Botan::short_version_string();
    name_str.insert(0, "Botan ");

    jstring name = env->NewStringUTF(name_str.c_str());
    double version = strtod(v_str, NULL);
    jstring info = env->NewStringUTF(info_str);

    return env->NewObject(provider_class, init, name, version, info);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Botan_setup(JNIEnv *env, jobject self){
    jmethodID provider_put = env->GetMethodID(provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    add_kpg(env, "ECDH", "BotanECDH", self, provider_put);
    add_kpg(env, "ECDSA", "BotanECDSA", self, provider_put);
    add_kpg(env, "ECKCDSA", "BotanECKCDSA", self, provider_put);
    add_kpg(env, "ECGDSA", "BotanECGDSA", self, provider_put);

    add_ka(env, "ECDH", "BotanECDH", self, provider_put);
    add_ka(env, "ECDHwithSHA1KDF", "BotanECDHwithSHA1KDF", self, provider_put);
    add_ka(env, "ECDHwithSHA224KDF", "BotanECDHwithSHA224KDF", self, provider_put);
    add_ka(env, "ECDHwithSHA256KDF", "BotanECDHwithSHA256KDF", self, provider_put);
    add_ka(env, "ECDHwithSHA384KDF", "BotanECDHwithSHA384KDF", self, provider_put);
    add_ka(env, "ECDHwithSHA512KDF", "BotanECDHwithSHA512KDF", self, provider_put);

    add_sig(env, "NONEwithECDSA", "BotanECDSAwithNONE", self, provider_put);
    add_sig(env, "SHA1withECDSA", "BotanECDSAwithSHA1", self, provider_put);
    add_sig(env, "SHA224withECDSA", "BotanECDSAwithSHA224", self, provider_put);
    add_sig(env, "SHA256withECDSA", "BotanECDSAwithSHA256", self, provider_put);
    add_sig(env, "SHA384withECDSA", "BotanECDSAwithSHA384", self, provider_put);
    add_sig(env, "SHA512withECDSA", "BotanECDSAwithSHA512", self, provider_put);

    add_sig(env, "NONEwithECKCDSA", "BotanECKCDSAwithNONE", self, provider_put);
    add_sig(env, "SHA1withECKCDSA", "BotanECKCDSAwithSHA1", self, provider_put);
    add_sig(env, "SHA224withECKCDSA", "BotanECKCDSAwithSHA224", self, provider_put);
    add_sig(env, "SHA256withECKCDSA", "BotanECKCDSAwithSHA256", self, provider_put);
    add_sig(env, "SHA384withECKCDSA", "BotanECKCDSAwithSHA384", self, provider_put);
    add_sig(env, "SHA512withECKCDSA", "BotanECKCDSAwithSHA512", self, provider_put);
    
    add_sig(env, "NONEwithECGDSA", "BotanECGDSAwithNONE", self, provider_put);
    add_sig(env, "SHA1withECGDSA", "BotanECGDSAwithSHA1", self, provider_put);
    add_sig(env, "SHA224withECGDSA", "BotanECGDSAwithSHA224", self, provider_put);
    add_sig(env, "SHA256withECGDSA", "BotanECGDSAwithSHA256", self, provider_put);
    add_sig(env, "SHA384withECGDSA", "BotanECGDSAwithSHA384", self, provider_put);
    add_sig(env, "SHA512withECGDSA", "BotanECGDSAwithSHA512", self, provider_put);

    init_classes(env, "Botan");
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_BotanLib_getCurves(JNIEnv *env, jobject self){
    jclass set_class = env->FindClass("java/util/TreeSet");

    jmethodID set_ctr = env->GetMethodID(set_class, "<init>", "()V");
    jmethodID set_add = env->GetMethodID(set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = env->NewObject(set_class, set_ctr);

    const std::set<std::string>& curves = Botan::EC_Group::known_named_groups();
    for (auto it = curves.begin(); it != curves.end(); ++it) {
        std::string curve_name = *it;
        jstring name_str = env->NewStringUTF(curve_name.c_str());
        env->CallBooleanMethod(result, set_add, name_str);
    }

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_keysizeSupported(JNIEnv *env, jobject self, jint keysize){
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_paramsSupported(JNIEnv *env, jobject self, jobject params){
    if (params == NULL) {
        return JNI_FALSE;
    }

    if (env->IsInstanceOf(params, ec_parameter_spec_class)) {
        jmethodID get_curve = env->GetMethodID(ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
        jobject curve = env->CallObjectMethod(params, get_curve);

        jmethodID get_field = env->GetMethodID(elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
        jobject field = env->CallObjectMethod(curve, get_field);

        if (env->IsInstanceOf(field, fp_field_class)) {
            return JNI_TRUE;
        }
    } else if (env->IsInstanceOf(params, ecgen_parameter_spec_class)) {
        const std::set<std::string>& curves = Botan::EC_Group::known_named_groups();
        jmethodID get_name = env->GetMethodID(ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (jstring) env->CallObjectMethod(params, get_name);
        const char *utf_name = env->GetStringUTFChars(name, NULL);
        std::string str_name(utf_name);
        env->ReleaseStringUTFChars(name, utf_name);
        if (curves.find(str_name) != curves.end()) {
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

static jobject biginteger_from_bigint(JNIEnv *env, const Botan::BigInt& bigint) {
    std::vector<uint8_t> bigint_data = Botan::BigInt::encode(bigint);
    jbyteArray bigint_array = env->NewByteArray(bigint_data.size());
    jbyte * bigint_bytes = env->GetByteArrayElements(bigint_array, NULL);
    std::copy(bigint_data.begin(), bigint_data.end(), bigint_bytes);
    env->ReleaseByteArrayElements(bigint_array, bigint_bytes, 0);

    jmethodID biginteger_init = env->GetMethodID(biginteger_class, "<init>", "(I[B)V");
    return env->NewObject(biginteger_class, biginteger_init, (jint) 1, bigint_array);
}

static Botan::BigInt bigint_from_biginteger(JNIEnv *env, jobject biginteger) {
    jmethodID to_byte_array = env->GetMethodID(biginteger_class, "toByteArray", "()[B");
    jbyteArray byte_array = (jbyteArray) env->CallObjectMethod(biginteger, to_byte_array);
    jsize byte_length = env->GetArrayLength(byte_array);
    jbyte *byte_data = env->GetByteArrayElements(byte_array, NULL);
    Botan::BigInt result((unsigned char *) byte_data, byte_length);
    env->ReleaseByteArrayElements(byte_array, byte_data, JNI_ABORT);
    return result;
}

static Botan::EC_Group group_from_params(JNIEnv *env, jobject params) {
    if (env->IsInstanceOf(params, ec_parameter_spec_class)) {
        jmethodID get_curve = env->GetMethodID(ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
        jobject elliptic_curve = env->CallObjectMethod(params, get_curve);
    
        jmethodID get_field = env->GetMethodID(elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
        jobject field = env->CallObjectMethod(elliptic_curve, get_field);

        jmethodID get_a = env->GetMethodID(elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
        jobject a = env->CallObjectMethod(elliptic_curve, get_a);
    
        jmethodID get_b = env->GetMethodID(elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
        jobject b = env->CallObjectMethod(elliptic_curve, get_b);
    
        jmethodID get_p = env->GetMethodID(fp_field_class, "getP", "()Ljava/math/BigInteger;");
        jobject p = env->CallObjectMethod(field, get_p);
    
        jmethodID get_g = env->GetMethodID(ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
        jobject g = env->CallObjectMethod(params, get_g);
    
        jmethodID get_x = env->GetMethodID(point_class, "getAffineX", "()Ljava/math/BigInteger;");
        jobject gx = env->CallObjectMethod(g, get_x);
    
        jmethodID get_y = env->GetMethodID(point_class, "getAffineY", "()Ljava/math/BigInteger;");
        jobject gy = env->CallObjectMethod(g, get_y);
    
        jmethodID get_n = env->GetMethodID(ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
        jobject n = env->CallObjectMethod(params, get_n);

        jmethodID get_h = env->GetMethodID(ec_parameter_spec_class, "getCofactor", "()I");
        jint h = env->CallIntMethod(params, get_h);

        Botan::BigInt pi = bigint_from_biginteger(env, p);
        Botan::BigInt ai = bigint_from_biginteger(env, a);
        Botan::BigInt bi = bigint_from_biginteger(env, b);

        Botan::BigInt gxi = bigint_from_biginteger(env, gx);
        Botan::BigInt gyi = bigint_from_biginteger(env, gy);

        Botan::BigInt ni = bigint_from_biginteger(env, n);
        Botan::BigInt hi(h);

        return Botan::EC_Group(pi, ai, bi, gxi, gyi, ni, hi);
    } else if (env->IsInstanceOf(params, ecgen_parameter_spec_class)) {
        jmethodID get_name = env->GetMethodID(ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (jstring) env->CallObjectMethod(params, get_name);
        const char *utf_name = env->GetStringUTFChars(name, NULL);
        std::string curve_name(utf_name);
        env->ReleaseStringUTFChars(name, utf_name);
        return Botan::EC_Group(curve_name);
    }
    return Botan::EC_Group();
}

static jobject params_from_group(JNIEnv *env, Botan::EC_Group group) {
    jobject p = biginteger_from_bigint(env, group.get_p());

    jmethodID fp_field_init = env->GetMethodID(fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject fp_field = env->NewObject(fp_field_class, fp_field_init, p);

    jobject a = biginteger_from_bigint(env, group.get_a());
    jobject b = biginteger_from_bigint(env, group.get_b());

    jmethodID elliptic_curve_init = env->GetMethodID(elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = env->NewObject(elliptic_curve_class, elliptic_curve_init, fp_field, a, b);

    const Botan::PointGFp& generator = group.get_base_point();
    jobject gx = biginteger_from_bigint(env, generator.get_affine_x());
    jobject gy = biginteger_from_bigint(env, generator.get_affine_y());

    jmethodID point_init = env->GetMethodID(point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject g = env->NewObject(point_class, point_init, gx, gy);

    const Botan::BigInt& order = group.get_order();
    jobject n = biginteger_from_bigint(env, order);

    const Botan::BigInt& cofactor = group.get_cofactor();
    jint h = (jint) cofactor.to_u32bit();

    jmethodID ec_parameter_spec_init = env->GetMethodID(ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    return env->NewObject(ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, n, h);
}

static jobject generate_from_group(JNIEnv* env, jobject self, Botan::EC_Group group) {
    jclass botan_kpg_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeKeyPairGeneratorSpi$Botan");
    jfieldID type_id = env->GetFieldID(botan_kpg_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char* type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    std::unique_ptr<Botan::EC_PrivateKey> skey;
    try {
        native_timing_start();
        if (type_str == "ECDH") {
            skey = std::make_unique<Botan::ECDH_PrivateKey>(rng, group);
        } else if (type_str == "ECDSA") {
            skey = std::make_unique<Botan::ECDSA_PrivateKey>(rng, group);
        } else if (type_str == "ECKCDSA") {
            skey = std::make_unique<Botan::ECKCDSA_PrivateKey>(rng, group);
        } else if (type_str == "ECGDSA") {
            skey = std::make_unique<Botan::ECGDSA_PrivateKey>(rng, group);
        }
        native_timing_stop();
    } catch (Botan::Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        return NULL;
    }

    jobject ec_param_spec = params_from_group(env, group);

    const Botan::PointGFp& pub_point = skey->public_point();
    std::vector<uint8_t> pub_data = pub_point.encode(Botan::PointGFp::UNCOMPRESSED);

    jbyteArray pub_bytearray = env->NewByteArray(pub_data.size());
    jbyte *pub_bytes = env->GetByteArrayElements(pub_bytearray, NULL);
    std::copy(pub_data.begin(), pub_data.end(), pub_bytes);
    env->ReleaseByteArrayElements(pub_bytearray, pub_bytes, 0);

    jobject ec_pub_param_spec = env->NewLocalRef(ec_param_spec);
    jmethodID ec_pub_init = env->GetMethodID(pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = env->NewObject(pubkey_class, ec_pub_init, pub_bytearray, ec_pub_param_spec);

    const Botan::BigInt& priv_scalar = skey->private_value();
    std::vector<uint8_t> priv_data = Botan::BigInt::encode(priv_scalar);

    jbyteArray priv_bytearray = env->NewByteArray(priv_data.size());
    jbyte *priv_bytes = env->GetByteArrayElements(priv_bytearray, NULL);
    std::copy(priv_data.begin(), priv_data.end(), priv_bytes);
    env->ReleaseByteArrayElements(priv_bytearray, priv_bytes, 0);

    jobject ec_priv_param_spec = env->NewLocalRef(ec_param_spec);
    jmethodID ec_priv_init = env->GetMethodID(privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = env->NewObject(privkey_class, ec_priv_init, priv_bytearray, ec_priv_param_spec);

    jmethodID keypair_init = env->GetMethodID(keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

    return env->NewObject(keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random){
    const std::set<std::string>& curves = Botan::EC_Group::known_named_groups();
    for (auto it = curves.begin(); it != curves.end(); ++it) {
        Botan::EC_Group curve_group = Botan::EC_Group(*it);
        size_t curve_size = curve_group.get_p_bits();
        if (curve_size == (size_t) keysize) {
            //generate on this group. Even thou no default groups are present...
            return generate_from_group(env, self, curve_group);
        }
    }

    throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
    return NULL;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random){
    Botan::EC_Group curve_group = group_from_params(env, params);
    return generate_from_group(env, self, curve_group);
}

static std::string get_kdf(const std::string& type_str, size_t *kdf_bits) {
    std::string kdf;
    size_t key_len = 0;
    if (type_str == "ECDH") {
        kdf = "Raw";
        //key len unused
    } else if (type_str == "ECDHwithSHA1KDF") {
        kdf = "KDF2(SHA-1)";
        key_len = 20;
    } else if (type_str == "ECDHwithSHA224KDF") {
        kdf = "KDF2(SHA-224)";
        key_len = 28;
    } else if (type_str == "ECDHwithSHA256KDF") {
        kdf = "KDF2(SHA-256)";
        key_len = 32;
    } else if (type_str == "ECDHwithSHA384KDF") {
        kdf = "KDF2(SHA-384)";
        key_len = 48;
    } else if (type_str == "ECDHwithSHA512KDF") {
        kdf = "KDF2(SHA-512)";
        key_len = 64;
    }

    if (*kdf_bits == 0) {
        *kdf_bits = key_len;
    }

    return kdf;
}

jbyteArray generate_secret(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    Botan::EC_Group curve_group = group_from_params(env, params);

    jsize privkey_length = env->GetArrayLength(privkey);
    jbyte *privkey_data = env->GetByteArrayElements(privkey, NULL);
    Botan::BigInt privkey_scalar((unsigned char *) privkey_data, privkey_length);
    env->ReleaseByteArrayElements(privkey, privkey_data, JNI_ABORT);

    Botan::ECDH_PrivateKey skey(rng, curve_group, privkey_scalar);

    jsize pubkey_length = env->GetArrayLength(pubkey);
    jbyte *pubkey_data = env->GetByteArrayElements(pubkey, NULL);
    Botan::PointGFp public_point = curve_group.OS2ECP((uint8_t*) pubkey_data, pubkey_length);
    env->ReleaseByteArrayElements(pubkey, pubkey_data, JNI_ABORT);

    Botan::ECDH_PublicKey pkey(curve_group, public_point);
    //TODO: do check_key here?

    jclass botan_ka_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeKeyAgreementSpi$Botan");
    jfieldID type_id = env->GetFieldID(botan_ka_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char *type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    size_t key_len = (get_kdf_bits(env, algorithm) + 7) / 8;
    std::string kdf = get_kdf(type_str, &key_len);

    Botan::PK_Key_Agreement ka(skey, rng, kdf);

    std::vector<uint8_t> derived;
    try {
        native_timing_start();
        derived = Botan::unlock(ka.derive_key(key_len, pkey.public_value()).bits_of());
        native_timing_stop();
    } catch (Botan::Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        return NULL;
    }
    jbyteArray result = env->NewByteArray(derived.size());
    jbyte *result_data = env->GetByteArrayElements(result, NULL);
    std::copy(derived.begin(), derived.end(), result_data);
    env->ReleaseByteArrayElements(result, result_data, 0);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Botan_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params){
    return generate_secret(env, self, pubkey, privkey, params, NULL);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Botan_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {
    jbyteArray secret = generate_secret(env, self, pubkey, privkey, params, algorithm);
    if (secret == NULL) {
        return NULL;
    }
    jmethodID spec_init = env->GetMethodID(secret_key_spec_class, "<init>", ("([BLjava/lang/String;)V"));
    return env->NewObject(secret_key_spec_class, spec_init, secret, algorithm);
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Botan_sign(JNIEnv *env, jobject self, jbyteArray data, jbyteArray privkey, jobject params){
    Botan::EC_Group curve_group = group_from_params(env, params);

    jclass botan_sig_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeSignatureSpi$Botan");
    jfieldID type_id = env->GetFieldID(botan_sig_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char *type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    jsize privkey_length = env->GetArrayLength(privkey);
    jbyte *privkey_bytes = env->GetByteArrayElements(privkey, NULL);
    Botan::BigInt privkey_scalar((uint8_t*) privkey_bytes, privkey_length);
    env->ReleaseByteArrayElements(privkey, privkey_bytes, JNI_ABORT);

    std::unique_ptr<Botan::EC_PrivateKey> skey;
    if (type_str.find("ECDSA") != std::string::npos) {
        skey = std::make_unique<Botan::ECDSA_PrivateKey>(rng, curve_group, privkey_scalar);
    } else if (type_str.find("ECKCDSA") != std::string::npos) {
        skey = std::make_unique<Botan::ECKCDSA_PrivateKey>(rng, curve_group, privkey_scalar);
    } else if (type_str.find("ECGDSA") != std::string::npos) {
        skey = std::make_unique<Botan::ECGDSA_PrivateKey>(rng, curve_group, privkey_scalar);
    }

    std::string emsa;
    if (type_str.find("NONE") != std::string::npos) {
        emsa = "Raw";
    } else if (type_str.find("SHA1") != std::string::npos) {
        emsa = "EMSA1(SHA-1)";
    } else if (type_str.find("SHA224") != std::string::npos) {
        emsa = "EMSA1(SHA-224)";
    } else if (type_str.find("SHA256") != std::string::npos) {
        emsa = "EMSA1(SHA-256)";
    } else if (type_str.find("SHA384") != std::string::npos) {
        emsa = "EMSA1(SHA-384)";
    } else if (type_str.find("SHA512") != std::string::npos) {
        emsa = "EMSA1(SHA-512)";
    }

    Botan::PK_Signer signer(*skey, rng, emsa, Botan::DER_SEQUENCE);

    jsize data_length = env->GetArrayLength(data);
    jbyte *data_bytes = env->GetByteArrayElements(data, NULL);
    std::vector<uint8_t> sig;
    try {
        native_timing_start();
        sig = signer.sign_message((uint8_t*) data_bytes, data_length, rng);
        native_timing_stop();
    } catch (Botan::Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);
        return NULL;
    }
    env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);

    jbyteArray result = env->NewByteArray(sig.size());
    jbyte *result_data = env->GetByteArrayElements(result, NULL);
    std::copy(sig.begin(), sig.end(), result_data);
    env->ReleaseByteArrayElements(result, result_data, 0);

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Botan_verify(JNIEnv *env, jobject self, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params){
    Botan::EC_Group curve_group = group_from_params(env, params);

    jclass botan_sig_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeSignatureSpi$Botan");
    jfieldID type_id = env->GetFieldID(botan_sig_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char *type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    jsize pubkey_length = env->GetArrayLength(pubkey);
    jbyte *pubkey_data = env->GetByteArrayElements(pubkey, NULL);
    Botan::PointGFp public_point = curve_group.OS2ECP((uint8_t*) pubkey_data, pubkey_length);
    env->ReleaseByteArrayElements(pubkey, pubkey_data, JNI_ABORT);

    std::unique_ptr<Botan::EC_PublicKey> pkey;
    if (type_str.find("ECDSA") != std::string::npos) {
        pkey = std::make_unique<Botan::ECDSA_PublicKey>(curve_group, public_point);
    } else if (type_str.find("ECKCDSA") != std::string::npos) {
        pkey = std::make_unique<Botan::ECKCDSA_PublicKey>(curve_group, public_point);
    } else if (type_str.find("ECGDSA") != std::string::npos) {
        pkey = std::make_unique<Botan::ECGDSA_PublicKey>(curve_group, public_point);
    }

    std::string emsa;
    if (type_str.find("NONE") != std::string::npos) {
        emsa = "Raw";
    } else if (type_str.find("SHA1") != std::string::npos) {
        emsa = "EMSA1(SHA-1)";
    } else if (type_str.find("SHA224") != std::string::npos) {
        emsa = "EMSA1(SHA-224)";
    } else if (type_str.find("SHA256") != std::string::npos) {
        emsa = "EMSA1(SHA-256)";
    } else if (type_str.find("SHA384") != std::string::npos) {
        emsa = "EMSA1(SHA-384)";
    } else if (type_str.find("SHA512") != std::string::npos) {
        emsa = "EMSA1(SHA-512)";
    }

    Botan::PK_Verifier verifier(*pkey, emsa, Botan::DER_SEQUENCE);

    jsize data_length = env->GetArrayLength(data);
    jsize sig_length = env->GetArrayLength(signature);
    jbyte *data_bytes = env->GetByteArrayElements(data, NULL);
    jbyte *sig_bytes = env->GetByteArrayElements(signature, NULL);

    bool result;
    try {
        native_timing_start();
        result = verifier.verify_message((uint8_t*)data_bytes, data_length, (uint8_t*)sig_bytes, sig_length);
        native_timing_stop();
    } catch (Botan::Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);
        env->ReleaseByteArrayElements(signature, sig_bytes, JNI_ABORT);
        return JNI_FALSE;
    }
    env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);
    env->ReleaseByteArrayElements(signature, sig_bytes, JNI_ABORT);
    if (result) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}