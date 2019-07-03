#pragma once

#include <jni.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 *
 */
jboolean native_timing_supported();

/**
 *
 */
jlong native_timing_resolution();

/**
 *
 */
void native_timing_start();

/**
 *
 */
void native_timing_pause();

/**
 *
 */
void native_timing_restart();

/**
 *
 */
void native_timing_stop();

/**
 *
 */
jlong native_timing_last();

#ifdef __cplusplus
}
#endif