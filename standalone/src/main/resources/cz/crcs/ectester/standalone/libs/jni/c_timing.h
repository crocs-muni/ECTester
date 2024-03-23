#pragma once

#include <jni.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 *
 */
__attribute__((visibility("default"))) jlong native_timing_resolution();

/**
 *
 */
__attribute__((visibility("default"))) void native_timing_start();

/**
 *
 */
__attribute__((visibility("default"))) void native_timing_pause();

/**
 *
 */
__attribute__((visibility("default"))) void native_timing_restart();

/**
 *
 */
__attribute__((visibility("default"))) void native_timing_stop();

/**
 *
 */
__attribute__((visibility("default"))) jlong native_timing_last();



#ifdef __cplusplus
}
#endif
