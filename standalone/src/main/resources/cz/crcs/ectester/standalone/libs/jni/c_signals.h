#pragma once

#include <jni.h>
#include <setjmp.h>
#include <signal.h>

#define TIMEOUT 5

/**
 *
 */
void init_signals_c(jmp_buf *env, unsigned int timeout);

/**
 *
 */
sigjmp_buf *get_jmpbuf_c();

/**
 *
 */
void deinit_signals_c();

/**
 *
 */
bool get_timedout_c();

/**
 *
 */
jobject get_siginfo_c(JNIEnv *env);


#define SIG_TRY(timeout) 	init_signals_c(get_jmpbuf_c(), timeout); \
							if (!sigsetjmp(*get_jmpbuf_c(), 1))
#define SIG_CATCH() deinit_signals_c();
#define SIG_DEINIT() deinit_signals_c();
#define SIG_HANDLE(env) do { \
							jobject siginfo = get_siginfo_c(env); \
							if (siginfo != NULL) { \
								jclass sigexception_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/SignalException"); \
								jmethodID new_sigexception = (*env)->GetMethodID(env, sigexception_class, "<init>", "(Lcz/crcs/ectester/standalone/libs/jni/SigInfo;)V"); \
								jobject sigexception = (*env)->NewObject(env, sigexception_class, new_sigexception, siginfo); \
								(*env)->Throw(env, sigexception); \
							} \
							if (get_timedout_c()) { \
								jclass timeoutexception_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/TimeoutException"); \
								(*env)->ThrowNew(env, timeoutexception_class, "Operation timed out."); \
							} \
						} while (0)
#define SIG_CATCH_HANDLE(env) SIG_CATCH(); \
							  SIG_HANDLE(env)
