#include "native.h"
#include <string>
#include <botan/botan.h>

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

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_BotanLib
 * Method:    getCurves
 * Signature: ()Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_BotanLib_getCurves(JNIEnv *env, jobject self){

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    keysizeSupported
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_keysizeSupported(JNIEnv *env, jobject self, jint keysize){

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    paramsSupported
 * Signature: (Ljava/security/spec/AlgorithmParameterSpec;)Z
 */
JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_paramsSupported(JNIEnv *env, jobject self, jobject params){

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    generate
 * Signature: (ILjava/security/SecureRandom;)Ljava/security/KeyPair;
 */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random){

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_Botan
 * Method:    generate
 * Signature: (Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)Ljava/security/KeyPair;
 */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Botan_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random){

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_Botan
 * Method:    generateSecret
 * Signature: ([B[BLjava/security/spec/ECParameterSpec;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Botan_generateSecret(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params){

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_Botan
 * Method:    sign
 * Signature: ([B[BLjava/security/spec/ECParameterSpec;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Botan_sign(JNIEnv *env, jobject self, jbyteArray data, jbyteArray privkey, jobject params){

}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_Botan
 * Method:    verify
 * Signature: ([B[B[BLjava/security/spec/ECParameterSpec;)Z
 */
JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Botan_verify(JNIEnv *env, jobject self, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params){

}