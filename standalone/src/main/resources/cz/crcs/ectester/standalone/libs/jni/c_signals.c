#include "c_utils.h"
#include "c_signals.h"

#if __linux || __posix

#include <signal.h>
#include <setjmp.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>

static siginfo_t last_siginfo;
static bool initialized = false;
static bool caught = false;
static bool timedout = false;
static sigjmp_buf buf;
static sigjmp_buf *target = NULL;

struct timer_arg {
	unsigned int timeout;
	pthread_t main_thread;
};
static struct timer_arg ta;
static pthread_t timer_thread;

void handler(int signo, siginfo_t *info, void *context) {
	//printf("Signal, %i\n", signo);
	last_siginfo = *info;
	caught = true;
	siglongjmp(*target, 1);
}

void alarm_handler(int signo) {
	//printf("Alarm\n");
	timedout = true;
	siglongjmp(*target, 1);
}


sigjmp_buf *get_jmpbuf_c() {
	return &buf;
}

static struct sigaction old_segv;
static struct sigaction old_abrt;
static struct sigaction old_alrm;

void *timer(void *arg) {
	sleep(ta.timeout);
	pthread_kill(ta.main_thread, SIGALRM);
	return NULL;
}

void init_signals_c(sigjmp_buf *env, unsigned int timeout) {
	//printf("Initializing signals!\n");
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

	ta.timeout = timeout;
	ta.main_thread = pthread_self();

	pthread_create(&timer_thread, NULL, timer, (void *)&ta);
}


void deinit_signals_c() {
	//printf("Deinitializing signals!\n");
	pthread_cancel(timer_thread);

	sigaction(SIGSEGV, &old_segv, NULL);
	sigaction(SIGABRT, &old_abrt, NULL);
	sigaction(SIGALRM, &old_alrm, NULL);

	target = NULL;
	initialized = false;
}

bool get_timedout_c() {
	return timedout;
}

jobject get_siginfo_c(JNIEnv *env) {
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