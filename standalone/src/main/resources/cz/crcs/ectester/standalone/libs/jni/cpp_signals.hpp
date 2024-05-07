#pragma once

#include <jni.h>
#include <setjmp.h>
#include <signal.h>

#define TIMEOUT 5

extern "C"
{

/**
 *
 */
void init_signals_cpp(jmp_buf *env, unsigned int timeout);

/**
 *
 */
sigjmp_buf *get_jmpbuf_cpp();

/**
 *
 */
void deinit_signals_cpp();

/**
 *
 */
bool get_timedout_cpp();

/**
 *
 */
jobject get_siginfo_cpp(JNIEnv *env);


#define SIG_TRY(timeout) 	init_signals_cpp(get_jmpbuf_cpp(), timeout); \
							if (!sigsetjmp(*get_jmpbuf_cpp(), 1))
#define SIG_CATCH() deinit_signals_cpp();
#define SIG_DEINIT() deinit_signals_cpp();
#define SIG_HANDLE(env) do { \
							jobject siginfo = get_siginfo_cpp(env); \
							if (siginfo != NULL) { \
								jclass sigexception_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/SignalException"); \
								jmethodID new_sigexception = env->GetMethodID(sigexception_class, "<init>", "(Lcz/crcs/ectester/standalone/libs/jni/SigInfo;)V"); \
								jobject sigexception = env->NewObject(sigexception_class, new_sigexception, siginfo); \
								env->Throw((jthrowable) sigexception); \
							} \
							if (get_timedout_cpp()) { \
								jclass timeoutexception_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/TimeoutException"); \
								env->ThrowNew(timeoutexception_class, "Operation timed out."); \
							} \
						} while (0)
#define SIG_CATCH_HANDLE(env) SIG_CATCH(); \
							  SIG_HANDLE(env)


}