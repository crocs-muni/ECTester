#include <jni.h>
#include <stdbool.h>
#include "prng/prng.h"

extern prng_state preload_prng_state;
extern bool preload_prng_enabled;

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_NativeECLibrary_setupDeterministicPRNG(JNIEnv *env, jobject self, jbyteArray seed) {
	jsize seed_length = (*env)->GetArrayLength(env, seed);
	jbyte *seed_data = (*env)->GetByteArrayElements(env, seed, NULL);

	preload_prng_enabled = true;
	prng_init(&preload_prng_state);
    prng_seed(&preload_prng_state, seed_data, seed_length);

	(*env)->ReleaseByteArrayElements(env, seed, seed_data, JNI_ABORT);
	return JNI_TRUE;
}