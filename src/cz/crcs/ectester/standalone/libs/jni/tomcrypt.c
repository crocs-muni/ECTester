#include "native.h"
#include <stdio.h>
#define LTM_DESC
#include <tomcrypt.h>

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TomcryptLib_createProvider(JNIEnv *env, jobject this) {
    jclass provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/TomCryptProvider");

    jmethodID init = (*env)->GetMethodID(env, provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");
    if (init == NULL) {
        return NULL;
    }
    jstring name =  (*env)->NewStringUTF(env, "libtomcrypt " SCRYPT);
    double version = strtod(SCRYPT, NULL);
    return (*env)->NewObject(env, provider_class, init, name, version, name);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_TomCryptProvider_setup(JNIEnv *env, jobject this) {
    ltc_mp = ltm_desc;
    /* Just test ecc key generation at this time. */
    ecc_key mykey;
    prng_state prng;
    int err;
    /* register yarrow */
    if (register_prng(&yarrow_desc) == -1) {
        printf("Error registering Yarrow\n");
        return;
    }
    /* setup the PRNG */
    if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
        printf("Error setting up PRNG, %s\n", error_to_string(err));
        return;
    }
    /* make a 192-bit ECC key */
    if ((err = ecc_make_key(&prng, find_prng("yarrow"), 24, &mykey)) != CRYPT_OK) {
        printf("Error making key: %s\n", error_to_string(err));
        return;
    }
    return;
}