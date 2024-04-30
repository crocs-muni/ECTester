#include "c_utils.h"
#include "c_signals.h"

#if __linux || __posix

#include <signal.h>
#include <setjmp.h>
#include <stdbool.h>

// TODO: Handle alarms properly.
//       Create a new thread, make it sleep, then send alarm to the main thread.

static siginfo_t last_siginfo;
static bool initialized = false;
static bool caught = false;
static bool timedout = false;
static jmp_buf *target = NULL;

void handler(int signo, siginfo_t *info, void *context) {
	last_siginfo = *info;
	caught = true;
	longjmp(*target, 1);
}

void alarm_handler(int signo) {
	timedout = true;
}

static jmp_buf buf;

jmp_buf *get_jmpbuf() {
	return &buf;
}

static struct sigaction old_segv;
static struct sigaction old_abrt;
static struct sigaction old_alrm;

void init_signals(jmp_buf *env) {
	struct sigaction action;
	action.sa_sigaction = handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO;

	sigaction(SIGSEGV, &action, &old_segv);
	sigaction(SIGABRT, &action, &old_abrt);

	struct sigaction alarm_action;
	alarm_action.sa_handler = alarm_handler;
	sigemptyset(&alarm_action.sa_mask);
	alarm_action.sa_flags = 0;
	sigaction(SIGALRM, &alarm_action, &old_alrm);

	target = env;
	initialized = true;
	caught = false;
	timedout = false;
}


void deinit_signals() {
	sigaction(SIGSEGV, NULL, &old_segv);
	sigaction(SIGABRT, NULL, &old_abrt);
	sigaction(SIGALRM, NULL, &old_alrm);

	target = NULL;
	initialized = false;
}

bool get_timedout() {
	return timedout;
}

jobject get_siginfo(JNIEnv *env) {
	if (!caught) {
		return NULL;
	}

	jclass local_siginfo_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/SigInfo");
	jmethodID siginfo_init = (*env)->GetMethodID(env, local_siginfo_class, "<init>", "(IIIIIJIJJ)V");
	return (*env)->NewObject(env, local_siginfo_class, siginfo_init,
							 (jint)  last_siginfo.si_signo,
							 (jint)  last_siginfo.si_code,
							 (jint)  last_siginfo.si_errno,
							 (jint)  last_siginfo.si_pid,
							 (jint)  last_siginfo.si_uid,
							 (jlong) last_siginfo.si_addr,
							 (jint)  last_siginfo.si_status,
							 (jlong) last_siginfo.si_band,
							 (jlong) 0);
}

#endif