#include "c_timing.h"

#if _POSIX_TIMERS > 0

#include <time.h>


static struct timespec start = {0};
static struct timespec end = {0};
static jlong partial = 0;

jboolean native_timing_supported() {
    return JNI_TRUE;
}

jlong native_timing_resolution() {
    struct timespec timeval;
    clock_getres(CLOCK_MONOTONIC, &timeval);
    return timeval.tv_nsec;
}

void native_timing_start() {
    partial = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
}

void native_timing_pause() {
    clock_gettime(CLOCK_MONOTONIC, &end);
    partial += (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
}

void native_timing_restart() {
    clock_gettime(CLOCK_MONOTONIC, &start);
}

void native_timing_stop() {
    clock_gettime(CLOCK_MONOTONIC, &end);
}

jlong native_timing_last() {
    jlong res = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec) + partial;
    if (res < 0) {
        return 0;
    } else {
        return res;
    }
}

#elif defined(__WIN32__) || defined(_MSC_VER)

#include <Windows.h>

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