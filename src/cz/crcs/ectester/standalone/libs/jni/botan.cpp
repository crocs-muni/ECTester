#include "native.h"
#include <string>
#include <botan/botan.h>
#include <botan/ec_group.h>
#include <botan/ecc_key.h>
#include <botan/ecdsa.h>
#include <botan/eckcdsa.h>
#include <botan/ecgdsa.h>
#include <botan/ecdh.h>
#include <botan/pubkey.h>
#include "cpp_utils.hpp"

static jclass provider_class;

/*
 * Class:     cz_crcs_ectester_standalone_libs_BotanLib
 * Method:    createProvider
 * Signature: ()Ljava/security/Provider;
 */
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

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeProvider_Botan
 * Method:    setup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Botan_setup(JNIEnv *env, jobject self){
    jmethodID provider_put = env->GetMethodID(provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    jstring ecdh = env->NewStringUTF("KeyPairGenerator.ECDH");
    jstring ecdh_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$BotanECDH");
    env->CallObjectMethod(self, provider_put, ecdh, ecdh_value);

    jstring ecdsa = env->NewStringUTF("KeyPairGenerator.ECDSA");
    jstring ecdsa_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$BotanECDSA");
    env->CallObjectMethod(self, provider_put, ecdsa, ecdsa_value);

    jstring eckcdsa = env->NewStringUTF("KeyPairGenerator.ECKCDSA");
    jstring eckcdsa_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$BotanECKCDSA");
    env->CallObjectMethod(self, provider_put, eckcdsa, eckcdsa_value);
    
    jstring ecgdsa = env->NewStringUTF("KeyPairGenerator.ECGDSA");
    jstring ecgdsa_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$BotanECGDSA");
    env->CallObjectMethod(self, provider_put, ecgdsa, ecgdsa_value);

    jstring ecdh_ka = env->NewStringUTF("KeyAgreement.ECDH");
    jstring ecdh_ka_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$BotanECDH");
    env->CallObjectMethod(self, provider_put, ecdh_ka, ecdh_ka_value);

    jstring ecdh_sha1_ka = env->NewStringUTF("KeyAgreement.ECDHwithSHA1KDF");
    jstring ecdh_sha1_ka_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$BotanECDHwithSHA1KDF");
    env->CallObjectMethod(self, provider_put, ecdh_sha1_ka, ecdh_sha1_ka_value);

    jstring ecdh_sha224_ka = env->NewStringUTF("KeyAgreement.ECDHwithSHA224KDF");
    jstring ecdh_sha224_ka_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$BotanECDHwithSHA224KDF");
    env->CallObjectMethod(self, provider_put, ecdh_sha224_ka, ecdh_sha224_ka_value);

    jstring ecdh_sha256_ka = env->NewStringUTF("KeyAgreement.ECDHwithSHA256KDF");
    jstring ecdh_sha256_ka_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$BotanECDHwithSHA256KDF");
    env->CallObjectMethod(self, provider_put, ecdh_sha256_ka, ecdh_sha256_ka_value);

    jstring ecdh_sha384_ka = env->NewStringUTF("KeyAgreement.ECDHwithSHA384KDF");
    jstring ecdh_sha384_ka_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$BotanECDHwithSHA384KDF");
    env->CallObjectMethod(self, provider_put, ecdh_sha384_ka, ecdh_sha384_ka_value);

    jstring ecdh_sha512_ka = env->NewStringUTF("KeyAgreement.ECDHwithSHA512KDF");
    jstring ecdh_sha512_ka_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$BotanECDHwithSHA512KDF");
    env->CallObjectMethod(self, provider_put, ecdh_sha512_ka, ecdh_sha512_ka_value);

    jstring ecdsa_sig = env->NewStringUTF("Signature.NONEwithECDSA");
    jstring ecdsa_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECDSAwithNONE");
    env->CallObjectMethod(self, provider_put, ecdsa_sig, ecdsa_sig_value);

    jstring ecdsa_sha1_sig = env->NewStringUTF("Signature.SHA1withECDSA");
    jstring ecdsa_sha1_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECDSAwithSHA1");
    env->CallObjectMethod(self, provider_put, ecdsa_sha1_sig, ecdsa_sha1_sig_value);

    jstring ecdsa_sha224_sig = env->NewStringUTF("Signature.SHA224withECDSA");
    jstring ecdsa_sha224_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECDSAwithSHA224");
    env->CallObjectMethod(self, provider_put, ecdsa_sha224_sig, ecdsa_sha224_sig_value);

    jstring ecdsa_sha256_sig = env->NewStringUTF("Signature.SHA256withECDSA");
    jstring ecdsa_sha256_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECDSAwithSHA256");
    env->CallObjectMethod(self, provider_put, ecdsa_sha256_sig, ecdsa_sha256_sig_value);

    jstring ecdsa_sha384_sig = env->NewStringUTF("Signature.SHA384withECDSA");
    jstring ecdsa_sha384_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECDSAwithSHA384");
    env->CallObjectMethod(self, provider_put, ecdsa_sha384_sig, ecdsa_sha384_sig_value);

    jstring ecdsa_sha512_sig = env->NewStringUTF("Signature.SHA512withECDSA");
    jstring ecdsa_sha512_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECDSAwithSHA512");
    env->CallObjectMethod(self, provider_put, ecdsa_sha512_sig, ecdsa_sha512_sig_value);
    
    jstring eckcdsa_sig = env->NewStringUTF("Signature.NONEwithECKCDSA");
    jstring eckcdsa_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECKCDSAwithNONE");
    env->CallObjectMethod(self, provider_put, eckcdsa_sig, eckcdsa_sig_value);

    jstring eckcdsa_sha1_sig = env->NewStringUTF("Signature.SHA1withECKCDSA");
    jstring eckcdsa_sha1_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECKCDSAwithSHA1");
    env->CallObjectMethod(self, provider_put, eckcdsa_sha1_sig, eckcdsa_sha1_sig_value);

    jstring eckcdsa_sha224_sig = env->NewStringUTF("Signature.SHA224withECKCDSA");
    jstring eckcdsa_sha224_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECKCDSAwithSHA224");
    env->CallObjectMethod(self, provider_put, eckcdsa_sha224_sig, eckcdsa_sha224_sig_value);

    jstring eckcdsa_sha256_sig = env->NewStringUTF("Signature.SHA256withECKCDSA");
    jstring eckcdsa_sha256_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECKCDSAwithSHA256");
    env->CallObjectMethod(self, provider_put, eckcdsa_sha256_sig, eckcdsa_sha256_sig_value);

    jstring eckcdsa_sha384_sig = env->NewStringUTF("Signature.SHA384withECKCDSA");
    jstring eckcdsa_sha384_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECKCDSAwithSHA384");
    env->CallObjectMethod(self, provider_put, eckcdsa_sha384_sig, eckcdsa_sha384_sig_value);

    jstring eckcdsa_sha512_sig = env->NewStringUTF("Signature.SHA512withECKCDSA");
    jstring eckcdsa_sha512_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECKCDSAwithSHA512");
    env->CallObjectMethod(self, provider_put, eckcdsa_sha512_sig, eckcdsa_sha512_sig_value);

    jstring ecgdsa_sig = env->NewStringUTF("Signature.NONEwithECGDSA");
    jstring ecgdsa_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECGDSAwithNONE");
    env->CallObjectMethod(self, provider_put, ecgdsa_sig, ecgdsa_sig_value);

    jstring ecgdsa_sha1_sig = env->NewStringUTF("Signature.SHA1withECGDSA");
    jstring ecgdsa_sha1_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECGDSAwithSHA1");
    env->CallObjectMethod(self, provider_put, ecgdsa_sha1_sig, ecgdsa_sha1_sig_value);

    jstring ecgdsa_sha224_sig = env->NewStringUTF("Signature.SHA224withECGDSA");
    jstring ecgdsa_sha224_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECGDSAwithSHA224");
    env->CallObjectMethod(self, provider_put, ecgdsa_sha224_sig, ecgdsa_sha224_sig_value);

    jstring ecgdsa_sha256_sig = env->NewStringUTF("Signature.SHA256withECGDSA");
    jstring ecgdsa_sha256_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECGDSAwithSHA256");
    env->CallObjectMethod(self, provider_put, ecgdsa_sha256_sig, ecgdsa_sha256_sig_value);

    jstring ecgdsa_sha384_sig = env->NewStringUTF("Signature.SHA384withECGDSA");
    jstring ecgdsa_sha384_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECGDSAwithSHA384");
    env->CallObjectMethod(self, provider_put, ecgdsa_sha384_sig, ecgdsa_sha384_sig_value);

    jstring ecgdsa_sha512_sig = env->NewStringUTF("Signature.SHA512withECGDSA");
    jstring ecgdsa_sha512_sig_value = env->NewStringUTF("cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$BotanECGDSAwithSHA512");
    env->CallObjectMethod(self, provider_put, ecgdsa_sha512_sig, ecgdsa_sha512_sig_value);

    init_classes(env, "Botan");
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_BotanLib
 * Method:    getCurves
 * Signature: ()Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_BotanLib_getCurves(JNIEnv *env, jobject self){
    jclass hash_set_class = env->FindClass("java/util/TreeSet");

    jmethodID hash_set_ctr = env->GetMethodID(hash_set_class, "<init>", "()V");
    jmethodID hash_set_add = env->GetMethodID(hash_set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = env->NewObject(hash_set_class, hash_set_ctr);

    const std::set<std::string>& curves = Botan::EC_Group::known_named_groups();
    for (auto it = curves.begin(); it != curves.end(); ++it) {
        std::string curve_name = *it;
        jstring name_str = env->NewStringUTF(curve_name.c_str());
        env->CallBooleanMethod(result, hash_set_add, name_str);
    }

    return result;
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    keysizeSupported
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_keysizeSupported(JNIEnv *env, jobject self, jint keysize){
    return JNI_TRUE;
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    paramsSupported
 * Signature: (Ljava/security/spec/AlgorithmParameterSpec;)Z
 */
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
    env->ReleaseByteArrayElements(bigint_array, bigint_bytes, JNI_COMMIT);

    jmethodID biginteger_init = env->GetMethodID(biginteger_class, "<init>", "(I[B)V");
    return env->NewObject(biginteger_class, biginteger_init, (jint) 1, bigint_array);
}

static Botan::BigInt bigint_from_biginteger(JNIEnv *env, jobject biginteger) {
    jmethodID to_byte_array = env->GetMethodID(biginteger_class, "toByteArray", "()[B");
    jbyteArray byte_array = (jbyteArray) env->CallObjectMethod(biginteger, to_byte_array);
    jsize byte_length = env->GetArrayLength(byte_array);
    jbyte *byte_data = env->GetByteArrayElements(byte_array, NULL);
    Botan::BigInt result((unsigned uint8_t*) byte_data, byte_length);
    env->ReleaseByteArrayElements(byte_array, byte_data, JNI_ABORT);
    return result;
}

static Botan::EC_Group group_from_params(JNIEnv *env, jobject params) {
    if (env->IsInstanceOf(params, ec_parameter_spec_class)) {
        jmethodID get_curve = env->GetMethodID(ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
        jobject elliptic_curve = env->CallObjectMethod(params, get_curve);
    
        jmethodID get_field = env->GetMethodID(elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
        jobject field = env->CallObjectMethod(elliptic_curve, get_field);
    
        jmethodID get_bits = env->GetMethodID(fp_field_class, "getFieldSize", "()I");
        jint bits = env->CallIntMethod(field, get_bits);
        jint bytes = (bits + 7) / 8;

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
        Botan::CurveGFp curve(pi, ai, bi);

        Botan::BigInt gxi = bigint_from_biginteger(env, gx);
        Botan::BigInt gyi = bigint_from_biginteger(env, gy);
        Botan::PointGFp generator(curve, gxi, gyi);

        Botan::BigInt ni = bigint_from_biginteger(env, n);
        Botan::BigInt hi(h);

        return Botan::EC_Group(curve, generator, ni, hi);
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
    const Botan::CurveGFp& curve = group.get_curve();
    jobject p = biginteger_from_bigint(env, curve.get_p());

    jmethodID fp_field_init = env->GetMethodID(fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    jobject fp_field = env->NewObject(fp_field_class, fp_field_init, p);

    jobject a = biginteger_from_bigint(env, curve.get_a());
    jobject b = biginteger_from_bigint(env, curve.get_b());

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
    Botan::AutoSeeded_RNG rng;

    jclass botan_kpg_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeKeyPairGeneratorSpi$Botan");
    jfieldID type_id = env->GetFieldID(botan_kpg_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char* type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    std::unique_ptr<Botan::EC_PrivateKey> skey;
    try {
        if (type_str == "ECDH") {
            skey = std::make_unique<Botan::ECDH_PrivateKey>(rng, group);
        } else if (type_str == "ECDSA") {
            skey = std::make_unique<Botan::ECDSA_PrivateKey>(rng, group);
        } else if (type_str == "ECKCDSA") {
            skey = std::make_unique<Botan::ECKCDSA_PrivateKey>(rng, group);
        } else if (type_str == "ECGDSA") {
            skey = std::make_unique<Botan::ECGDSA_PrivateKey>(rng, group);
        }
    } catch (Botan::Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        return NULL;
    }

    jobject ec_param_spec = params_from_group(env, group);

    const Botan::PointGFp& pub_point = skey->public_point();
    std::vector<uint8_t> pub_data = Botan::unlock(Botan::EC2OSP(pub_point, Botan::PointGFp::UNCOMPRESSED));

    jbyteArray pub_bytearray = env->NewByteArray(pub_data.size());
    jbyte *pub_bytes = env->GetByteArrayElements(pub_bytearray, NULL);
    std::copy(pub_data.begin(), pub_data.end(), pub_bytes);
    env->ReleaseByteArrayElements(pub_bytearray, pub_bytes, JNI_COMMIT);

    jobject ec_pub_param_spec = env->NewLocalRef(ec_param_spec);
    jmethodID ec_pub_init = env->GetMethodID(pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = env->NewObject(pubkey_class, ec_pub_init, pub_bytearray, ec_pub_param_spec);

    const Botan::BigInt& priv_scalar = skey->private_value();
    std::vector<uint8_t> priv_data = Botan::BigInt::encode(priv_scalar);

    jbyteArray priv_bytearray = env->NewByteArray(priv_data.size());
    jbyte *priv_bytes = env->GetByteArrayElements(priv_bytearray, NULL);
    std::copy(priv_data.begin(), priv_data.end(), priv_bytes);
    env->ReleaseByteArrayElements(priv_bytearray, priv_bytes, JNI_COMMIT);

    jobject ec_priv_param_spec = env->NewLocalRef(ec_param_spec);
    jmethodID ec_priv_init = env->GetMethodID(privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = env->NewObject(privkey_class, ec_priv_init, priv_bytearray, ec_priv_param_spec);

    jmethodID keypair_init = env->GetMethodID(keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

    return env->NewObject(keypair_class, keypair_init, pubkey, privkey);
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    generate
 * Signature: (ILjava/security/SecureRandom;)Ljava/security/KeyPair;
 */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random){
    const std::set<std::string>& curves = Botan::EC_Group::known_named_groups();
    for (auto it = curves.begin(); it != curves.end(); ++it) {
        Botan::EC_Group curve_group = Botan::EC_Group(*it);
        size_t curve_size = curve_group.get_curve().get_p().bits();
        if (curve_size == keysize) {
            //generate on this group. Even thou no default groups are present...
            return generate_from_group(env, self, curve_group);
        }
    }

    throw_new(env, "java/security/InvalidAlgorithmParameterException", "Curve not found.");
    return NULL;
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    generate
 * Signature: (Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)Ljava/security/KeyPair;
 */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random){
    Botan::EC_Group curve_group = group_from_params(env, params);
    return generate_from_group(env, self, curve_group);
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_Botan
 * Method:    generateSecret
 * Signature: ([B[BLjava/security/spec/ECParameterSpec;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Botan_generateSecret(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params){
    Botan::EC_Group curve_group = group_from_params(env, params);

    jsize privkey_length = env->GetArrayLength(privkey);
    jbyte *privkey_data = env->GetByteArrayElements(privkey, NULL);
    Botan::BigInt privkey_scalar((unsigned uint8_t*) privkey_data, privkey_length);
    env->ReleaseByteArrayElements(privkey, privkey_data, JNI_ABORT);

    Botan::AutoSeeded_RNG rng;

    Botan::ECDH_PrivateKey skey(rng, curve_group, privkey_scalar);

    jsize pubkey_length = env->GetArrayLength(pubkey);
    jbyte *pubkey_data = env->GetByteArrayElements(pubkey, NULL);
    Botan::PointGFp public_point = Botan::OS2ECP((uint8_t*) pubkey_data, pubkey_length, curve_group.get_curve());
    env->ReleaseByteArrayElements(pubkey, pubkey_data, JNI_ABORT);

    Botan::ECDH_PublicKey pkey(curve_group, public_point);
    //TODO: do check_key here?

    jclass botan_ka_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeKeyAgreementSpi$Botan");
    jfieldID type_id = env->GetFieldID(botan_ka_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char *type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    std::string kdf;
    size_t key_len = 0;
    if (type_str == "ECDH") {
        kdf = "Raw";
        //key len unused
    } else if (type_str == "ECDHwithSHA1KDF") {
        kdf = "KDF1(SHA-1)";
        key_len = 20;
    } else if (type_str == "ECDHwithSHA224KDF") {
        kdf = "KDF1(SHA-224)";
        key_len = 28;
    } else if (type_str == "ECDHwithSHA256KDF") {
        kdf = "KDF1(SHA-256)";
        key_len = 32;
    } else if (type_str == "ECDHwithSHA384KDF") {
        kdf = "KDF1(SHA-384)";
        key_len = 48;
    } else if (type_str == "ECDHwithSHA512KDF") {
        kdf = "KDF1(SHA-512)";
        key_len = 64;
    }

    Botan::PK_Key_Agreement ka(skey, rng, kdf);

    std::vector<uint8_t> derived;
    try {
        derived = Botan::unlock(ka.derive_key(key_len, pkey.public_value()).bits_of());
    } catch (Botan::Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        return NULL;
    }
    jbyteArray result = env->NewByteArray(derived.size());
    jbyte *result_data = env->GetByteArrayElements(result, NULL);
    std::copy(derived.begin(), derived.end(), result_data);
    env->ReleaseByteArrayElements(result, result_data, JNI_COMMIT);

    return result;
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_Botan
 * Method:    sign
 * Signature: ([B[BLjava/security/spec/ECParameterSpec;)[B
 */
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

    Botan::AutoSeeded_RNG rng;

    std::unique_ptr<Botan::EC_PrivateKey> skey;
    if (type_str.find("ECDSA") != std::string::npos) {
        skey = std::make_unique<Botan::ECDSA_PrivateKey>(rng, curve_group, privkey_scalar);
    } else if (type_str.find("ECKCDSA") != std::string::npos) {
        skey = std::make_unique<Botan::ECKCDSA_PrivateKey>(rng, curve_group, privkey_scalar);
    } else if (type_str.find("ECGDSA") != std::string::npos) {
        skey = std::make_unique<Botan::ECGDSA_PrivateKey>(rng, curve_group, privkey_scalar);
    }

    std::string kdf;
    if (type_str.find("NONE") != std::string::npos) {
        kdf = "Raw";
    } else if (type_str.find("SHA1") != std::string::npos) {
        kdf = "EMSA1(SHA-1)";
    } else if (type_str.find("SHA224") != std::string::npos) {
        kdf = "EMSA1(SHA-224)";
    } else if (type_str.find("SHA256") != std::string::npos) {
        kdf = "EMSA1(SHA-256)";
    } else if (type_str.find("SHA384") != std::string::npos) {
        kdf = "EMSA1(SHA-384)";
    } else if (type_str.find("SHA512") != std::string::npos) {
        kdf = "EMSA1(SHA-512)";
    }

    Botan::PK_Signer signer(*skey, rng, kdf, Botan::DER_SEQUENCE);

    jsize data_length = env->GetArrayLength(data);
    jbyte *data_bytes = env->GetByteArrayElements(data, NULL);
    std::vector<uint8_t> sig;
    try {
        sig = signer.sign_message((uint8_t*) data_bytes, data_length, rng);
    } catch (Botan::Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);
        return NULL;
    }
    env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);

    jbyteArray result = env->NewByteArray(sig.size());
    jbyte *result_data = env->GetByteArrayElements(result, NULL);
    std::copy(sig.begin(), sig.end(), result_data);
    env->ReleaseByteArrayElements(result, result_data, JNI_COMMIT);

    return result;
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_Botan
 * Method:    verify
 * Signature: ([B[B[BLjava/security/spec/ECParameterSpec;)Z
 */
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
    Botan::PointGFp public_point = Botan::OS2ECP((uint8_t*) pubkey_data, pubkey_length, curve_group.get_curve());
    env->ReleaseByteArrayElements(pubkey, pubkey_data, JNI_ABORT);

    std::unique_ptr<Botan::EC_PublicKey> pkey;
    if (type_str.find("ECDSA") != std::string::npos) {
        pkey = std::make_unique<Botan::ECDSA_PublicKey>(curve_group, public_point);
    } else if (type_str.find("ECKCDSA") != std::string::npos) {
        pkey = std::make_unique<Botan::ECKCDSA_PublicKey>(curve_group, public_point);
    } else if (type_str.find("ECGDSA") != std::string::npos) {
        pkey = std::make_unique<Botan::ECGDSA_PublicKey>(curve_group, public_point);
    }

    std::string kdf;
    if (type_str.find("NONE") != std::string::npos) {
        kdf = "Raw";
    } else if (type_str.find("SHA1") != std::string::npos) {
        kdf = "EMSA1(SHA-1)";
    } else if (type_str.find("SHA224") != std::string::npos) {
        kdf = "EMSA1(SHA-224)";
    } else if (type_str.find("SHA256") != std::string::npos) {
        kdf = "EMSA1(SHA-256)";
    } else if (type_str.find("SHA384") != std::string::npos) {
        kdf = "EMSA1(SHA-384)";
    } else if (type_str.find("SHA512") != std::string::npos) {
        kdf = "EMSA1(SHA-512)";
    }

    Botan::PK_Verifier verifier(*pkey, kdf, Botan::DER_SEQUENCE);

    jsize data_length = env->GetArrayLength(data);
    jsize sig_length = env->GetArrayLength(signature);
    jbyte *data_bytes = env->GetByteArrayElements(data, NULL);
    jbyte *sig_bytes = env->GetByteArrayElements(signature, NULL);

    bool result;
    try {
        result = verifier.verify_message((uint8_t*)data_bytes, data_length, (uint8_t*)sig_bytes, sig_length);
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