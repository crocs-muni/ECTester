#include "c_timing.h"
#include <time.h>

#if _POSIX_TIMERS > 0

struct timespec start = {0};
struct timespec end = {0};

jboolean native_timing_supported() {
    return JNI_TRUE;
}

jlong native_timing_resolution() {
    struct timespec timeval;
    clock_getres(CLOCK_MONOTONIC, &timeval);
    return timeval.tv_nsec;
}


void native_timing_start() {
    clock_gettime(CLOCK_MONOTONIC, &start);
}


void native_timing_stop() {
    clock_gettime(CLOCK_MONOTONIC, &end);
}


jlong native_timing_last() {
    jlong res = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
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

void native_timing_stop() {}

jlong native_timing_last() {
    return 0;
}

#endif