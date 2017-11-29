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

    jmethodID put = (*env)->GetMethodID(env, provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

/*    *//* Just test ecc key generation at this time. *//*
    ecc_key mykey;
    prng_state prng;
    int err;
    *//* register yarrow *//*
    if (register_prng(&yarrow_desc) == -1) {
        printf("Error registering Yarrow\n");
        return;
    }
    *//* setup the PRNG *//*
    if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
        printf("Error setting up PRNG, %s\n", error_to_string(err));
        return;
    }
    *//* make a 192-bit ECC key *//*
    if ((err = ecc_make_key(&prng, find_prng("yarrow"), 24, &mykey)) != CRYPT_OK) {
        printf("Error making key: %s\n", error_to_string(err));
        return;
    }
    return;*/
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