#pragma once

#include <jni.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 *
 */
void init_signals(jmp_buf *env);

/**
 *
 */
jmp_buf *get_jmpbuf();

/**
 *
 */
void deinit_signals();

/**
 *
 */
bool get_timedout();

/**
 *
 */
jobject get_siginfo(JNIEnv *env);


#define SIG_TRY() 	init_signals(get_jmpbuf()); \
					if (!setjmp(*get_jmpbuf()))
#define SIG_CATCH() deinit_signals();
#define SIG_HANDLE(env) do { \
					jobject siginfo = get_siginfo(env); \
					if (siginfo != NULL) { \
						jclass sigexception_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/SignalException"); \
						jmethodID new_sigexception = (*env)->GetMethodID(env, sigexception_class, "<init>", "(Lcz/crcs/ectester/standalone/libs/jni/SigInfo;)V"); \
						jobject sigexception = (*env)->NewObject(env, sigexception_class, new_sigexception, siginfo); \
						(*env)->Throw(env, sigexception); \
					} \
					if (get_timedout()) { \
						jclass timeoutexception_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/TimeoutException"); \
						(*env)->ThrowNew(env, timeoutexception_class, "Operation timed out."); \
					} \
} while (0)



#ifdef __cplusplus
}
#endif
