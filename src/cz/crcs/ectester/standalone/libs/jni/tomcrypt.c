#include "native.h"
#include <stdio.h>
#define LTM_DESC
#include <tomcrypt.h>

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TomcryptLib_createProvider(JNIEnv *env, jobject this) {
    jclass provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$TomCrypt");

    jmethodID init = (*env)->GetMethodID(env, provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    jstring name =  (*env)->NewStringUTF(env, "libtomcrypt " SCRYPT);
    double version = strtod(SCRYPT, NULL);

    return (*env)->NewObject(env, provider_class, init, name, version, name);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024TomCrypt_setup(JNIEnv *env, jobject this) {
    /* Initialize libtommath as the math lib. */
    ltc_mp = ltm_desc;

    jclass provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$TomCrypt");

    jmethodID provider_put = (*env)->GetMethodID(env, provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    jstring ec = (*env)->NewStringUTF(env, "KeyPairGenerator.EC");
    jstring ec_value = (*env)->NewStringUTF(env, "cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$TomCrypt");
    (*env)->CallObjectMethod(env, this, provider_put, ec, ec_value);

    jstring ecdh = (*env)->NewStringUTF(env, "KeyAgreement.ECDH");
    jstring ecdh_value = (*env)->NewStringUTF(env, "cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$TomCrypt");
    (*env)->CallObjectMethod(env, this, provider_put, ecdh, ecdh_value);

    jstring ecdsa = (*env)->NewStringUTF(env, "Signature.ECDSA");
    jstring ecdsa_value = (*env)->NewStringUTF(env, "cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$TomCrypt");
    (*env)->CallObjectMethod(env, this, provider_put, ecdsa, ecdsa_value);
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