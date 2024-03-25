#include "c_timing.h"

#if __linux || __posix

#include <unistd.h>
#include <time.h>
#include <string.h>

static unsigned long long tsc_start = 0;
static unsigned long long tsc_end = 0;
static unsigned long long tsc_partial = 0;
static const char *rdtsc_unit = "instr";

static inline unsigned long long rdtsc(void) {
    unsigned long long int x;
    __asm__ volatile ("rdtsc" : "=A" (x));
    return x;
}

static jlong rdtsc_timing_resolution() {
	return 1;
}

static void rdtsc_timing_start() {
    tsc_partial = 0;
    tsc_start = rdtsc();
}

static void rdtsc_timing_pause() {
	tsc_end = rdtsc();
    tsc_partial += tsc_end - tsc_start;
}

static void rdtsc_timing_restart() {
    tsc_start = rdtsc();
}

static void rdtsc_timing_stop() {
    tsc_end = rdtsc();
}

static jlong rdtsc_timing_last() {
    jlong res = (jlong) ((tsc_end - tsc_start) + tsc_partial);
    if (res < 0) {
        return 0;
    } else {
        return res;
    }
}

static struct timespec start = {0};
static struct timespec end = {0};
static jlong partial = 0;
static clockid_t clk_id = CLOCK_MONOTONIC_RAW;
static const char *clock_unit = "nano";

static jlong clock_timing_resolution() {
    struct timespec timeval;
    clock_getres(clk_id, &timeval);
    return timeval.tv_nsec;
}

static void clock_timing_start() {
    partial = 0;
    clock_gettime(clk_id, &start);
}

static void clock_timing_pause() {
    clock_gettime(clk_id, &end);
    partial += (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
}

static void clock_timing_restart() {
    clock_gettime(clk_id, (struct timespec *)&start);
}

static void clock_timing_stop() {
    clock_gettime(clk_id, (struct timespec *)&end);
}

static jlong clock_timing_last() {
    jlong res = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec) + partial;
    if (res < 0) {
        return 0;
    } else {
        return res;
    }
}

static jlong (*func_timing_resolution)() = &clock_timing_resolution;
static void (*func_timing_start)() = &clock_timing_start;
static void (*func_timing_pause)() = &clock_timing_pause;
static void (*func_timing_restart)() = &clock_timing_restart;
static void (*func_timing_stop)() = &clock_timing_stop;
static jlong (*func_timing_last)() = &clock_timing_last;
static const char *unit = "nano";

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_NativeECLibrary_getNativeTimingSupport(JNIEnv *env, jobject self) {
	jclass set_class = (*env)->FindClass(env, "java/util/TreeSet");

	jmethodID set_ctr = (*env)->GetMethodID(env, set_class, "<init>", "()V");
	jmethodID set_add = (*env)->GetMethodID(env, set_class, "add", "(Ljava/lang/Object;)Z");

	jobject result = (*env)->NewObject(env, set_class, set_ctr);
	(*env)->CallBooleanMethod(env, result, set_add, (*env)->NewStringUTF(env, "rdtsc"));
	(*env)->CallBooleanMethod(env, result, set_add, (*env)->NewStringUTF(env, "monotonic"));
	(*env)->CallBooleanMethod(env, result, set_add, (*env)->NewStringUTF(env, "monotonic-raw"));
	(*env)->CallBooleanMethod(env, result, set_add, (*env)->NewStringUTF(env, "cputime-processor"));
	(*env)->CallBooleanMethod(env, result, set_add, (*env)->NewStringUTF(env, "cputime-thread"));
	return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_NativeECLibrary_setNativeTimingType(JNIEnv *env, jobject self, jstring type) {
	const char *type_data = (*env)->GetStringUTFChars(env, type, NULL);

	if (strcmp(type_data, "rdtsc") == 0) {
		func_timing_resolution = &rdtsc_timing_resolution;
        func_timing_start = &rdtsc_timing_start;
        func_timing_pause = &rdtsc_timing_pause;
        func_timing_restart = &rdtsc_timing_restart;
        func_timing_stop = &rdtsc_timing_stop;
        func_timing_last = &rdtsc_timing_last;
        unit = rdtsc_unit;
		return JNI_TRUE;
	} else {
		if (strcmp(type_data, "monotonic") == 0) {
			clk_id = CLOCK_MONOTONIC;
		} else if (strcmp(type_data, "monotonic-raw") == 0) {
			clk_id = CLOCK_MONOTONIC_RAW;
		} else if (strcmp(type_data, "cputime-processor") == 0) {
			clk_id = CLOCK_PROCESS_CPUTIME_ID;
		} else if (strcmp(type_data, "cputime-thread") == 0) {
			clk_id = CLOCK_THREAD_CPUTIME_ID;
		} else {
			return JNI_FALSE;
		}

		func_timing_resolution = &clock_timing_resolution;
        func_timing_start = &clock_timing_start;
        func_timing_pause = &clock_timing_pause;
        func_timing_restart = &clock_timing_restart;
        func_timing_stop = &clock_timing_stop;
        func_timing_last = &clock_timing_last;
        unit = clock_unit;
        return JNI_TRUE;
	}
}

JNIEXPORT jlong JNICALL Java_cz_crcs_ectester_standalone_libs_NativeECLibrary_getNativeTimingResolution(JNIEnv *env, jobject self) {
	return native_timing_resolution();
}

JNIEXPORT jstring JNICALL Java_cz_crcs_ectester_standalone_libs_NativeECLibrary_getNativeTimingUnit(JNIEnv *env, jobject self) {
	return (*env)->NewStringUTF(env, unit);
}

JNIEXPORT jlong JNICALL Java_cz_crcs_ectester_standalone_libs_NativeECLibrary_getLastNativeTiming(JNIEnv *env, jobject self) {
	return native_timing_last();
}

jlong native_timing_resolution() {
	return func_timing_resolution();
}

void native_timing_start() {
	func_timing_start();
}

void native_timing_pause() {
	func_timing_pause();
}

void native_timing_restart() {
	func_timing_restart();
}

void native_timing_stop() {
	func_timing_stop();
}

jlong native_timing_last() {
	return func_timing_last();
}

#elif defined(__WIN32__) || defined(_MSC_VER)

#include <Windows.h>
#error TODO

static LARGE_INTEGER start = {0};
static LARGE_INTEGER end = {0};
static jlong partial = 0;

jboolean native_timing_supported() {
    return JNI_TRUE;
}

jlong native_timing_resolution() {
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return 1000000000 / freq.QuadPart;
}

void native_timing_start() {
    partial = 0;
    QueryPerformanceCounter(&start);
}

void native_timing_pause() {
    QueryPerformanceCounter(&end);
    partial = (end.QuadPart - start.QuadPart) * native_timing_resolution();
}

void native_timing_restart() {
    QueryPerformanceCounter(&start);
}

void native_timing_stop() {
    QueryPerformanceCounter(&end);
}

jlong native_timing_last() {
    jlong res = (end.QuadPart - start.QuadPart) * native_timing_resolution() + partial;
    if (res < 0) {
        return 0;
    } else {
        return res;
    }
}

#else

#error TODO
jboolean native_timing_supported() {
    return JNI_FALSE;
}

jlong native_timing_resolution() {
    return 0;
}

void native_timing_start() {}

void native_timing_pause() {}

void native_timing_restart() {}

void native_timing_stop() {}

jlong native_timing_last() {
    return 0;
}

#endif
