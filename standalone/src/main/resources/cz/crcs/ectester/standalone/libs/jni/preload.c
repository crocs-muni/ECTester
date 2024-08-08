#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>

typedef int (*open_t)(const char *pathname, int flags, ...);
static open_t real_open;
typedef int (*openat_t)(int fd, const char *pathname, int flags, ...);
static openat_t real_openat;
typedef ssize_t (*read_t)(int fd, void *buf, size_t count);
static read_t real_read;
typedef FILE *(*fopen_t)(const char *pathname, const char *mode);
static fopen_t real_fopen;
typedef size_t (*fread_t)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static fread_t real_fread;
typedef ssize_t (*getrandom_t)(void *buf, size_t buflen, unsigned int flags);
static getrandom_t real_getrandom;
typedef int (*getentropy_t)(void *buffer, size_t length);
static getentropy_t real_getentropy;
typedef long (*syscall_t)(long number, ...);
static syscall_t real_syscall;
typedef uint32_t (*arc4random_t)(void);
static arc4random_t real_arc4random;
typedef uint32_t (*arc4random_uniform_t)(uint32_t upper_bound);
static arc4random_uniform_t real_arc4random_uniform;
typedef void (*arc4random_buf_t)(void *buf, size_t n);
static arc4random_buf_t real_arc4random_buf;

static int *random_fds = NULL;
static size_t random_fds_used = 0;
static size_t random_fds_allocd = 0;

void check_random_fds() {
	if (random_fds_allocd == 0) {
		random_fds_allocd = 10;
		random_fds = calloc(random_fds_allocd, sizeof(int));
	} else if (random_fds_allocd == random_fds_used) {
		random_fds_allocd *= 2;
		random_fds = realloc(random_fds, random_fds_allocd * sizeof(int));
	}
}

void store_random_fd(int fd) {
	check_random_fds();
	random_fds[random_fds_used++] = fd;
}

int open(const char *pathname, int flags, ...) {
	if (!real_open) {
		real_open = dlsym(RTLD_NEXT, "open");
	}

	va_list args;
	va_start(args, flags);
	int mode = va_arg(args, int);
	va_end(args);

	int result = real_open(pathname, flags, mode);
	if (strcmp(pathname, "/dev/random") == 0 || strcmp(pathname, "/dev/urandom") == 0) {
		fprintf(stderr, "called open(%s, %i, %i)\n", pathname, flags, mode);
		store_random_fd(result);
	}
	return result;
}

int openat(int fd, const char *pathname, int flags, ...) {
	if (!real_openat) {
		real_openat = dlsym(RTLD_NEXT, "openat");
	}

	va_list args;
	va_start(args, flags);
	int mode = va_arg(args, int);
	va_end(args);

	int result = real_openat(fd, pathname, flags, mode);
	if (strcmp(pathname, "/dev/random") == 0 || strcmp(pathname, "/dev/urandom") == 0) {
		fprintf(stderr, "called openat(%s, %i, %i)\n", pathname, flags, mode);
		store_random_fd(result);
	}
	return result;
}

ssize_t read(int fd, void *buf, size_t count) {
	if (!real_read) {
		real_read = dlsym(RTLD_NEXT, "read");
	}

	for (int i = 0; i < random_fds_used; ++i) {
		int random_fd = random_fds[i];
		if (random_fd == fd) {
			fprintf(stderr, "read from random\n");
			uint8_t *buffer = (uint8_t*)buf;
			for (size_t c = 0; c < count; ++c) {
				buffer[c] = (uint8_t)0x00;
			}
			return count;
		}
	}

	return real_read(fd, buf, count);
}

static FILE **random_files = NULL;
static size_t random_files_used = 0;
static size_t random_files_allocd = 0;

void check_random_files() {
	if (random_files_allocd == 0) {
		random_files_allocd = 10;
		random_files = calloc(random_files_allocd, sizeof(FILE *));
	} else if (random_files_allocd == random_files_used) {
		random_files_allocd *= 2;
		random_files = realloc(random_files, random_files_allocd * sizeof(FILE*));
	}
}

void store_random_file(FILE *file) {
	check_random_files();
	random_files[random_files_used++] = file;
}

FILE *fopen(const char *pathname, const char *mode) {
	if (!real_fopen) {
		real_fopen = dlsym(RTLD_NEXT, "fopen");
	}

	FILE *result = real_fopen(pathname, mode);

	if (strcmp(pathname, "/dev/random") == 0 || strcmp(pathname, "/dev/urandom") == 0) {
		fprintf(stderr, "called fopen(%s, %s)\n", pathname, mode);
		store_random_file(result);
	}
	return result;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	if (!real_fread) {
		real_fread = dlsym(RTLD_NEXT, "fread");
	}

	for (int i = 0; i < random_files_used; ++i) {
		FILE *random_file = random_files[i];
		if (random_file == stream) {
			fprintf(stderr, "fread from random\n");
			uint8_t *buffer = (uint8_t*)ptr;
			for (size_t c = 0; c < size * nmemb; ++c) {
				buffer[c] = (uint8_t)0x00;
			}
			return size * nmemb;
		}
	}

	return real_fread(ptr, size, nmemb, stream);
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
	if (!real_getrandom) {
		real_getrandom = dlsym(RTLD_NEXT, "getrandom");
	}

	fprintf(stderr, "called getrandom(*, %lu, %u)\n", buflen, flags);
	uint8_t *buffer = (uint8_t*)buf;
	for (size_t i = 0; i < buflen; ++i) {
		buffer[i] = (uint8_t)0x00;
	}
	return buflen;
}

int getentropy(void *buffer, size_t length) {
	if (!real_getentropy) {
		real_getentropy = dlsym(RTLD_NEXT, "getentropy");
	}

	fprintf(stderr, "called getentropy(*, %lu)\n", length);
	uint8_t *buf = (uint8_t*)buffer;
	for (size_t i = 0; i < length; ++i) {
		buf[i] = (uint8_t)0x00;
	}
	return 0;
}

long syscall(long number, ...) {
	if (!real_syscall) {
		real_syscall = dlsym(RTLD_NEXT, "syscall");
	}
	va_list args;

	va_start(args, number);
	long int a0 = va_arg(args, long int);
	long int a1 = va_arg(args, long int);
	long int a2 = va_arg(args, long int);
	long int a3 = va_arg(args, long int);
	long int a4 = va_arg(args, long int);
	long int a5 = va_arg(args, long int);
	va_end(args);

	if (number == SYS_getrandom) {
		fprintf(stderr, "called syscall(getrandom, %li, %li, %li, %li, %li, %li)\n", a0, a1, a2, a3, a4, a5);
		uint8_t *buf = (uint8_t*)a0;
		long n = a1;
		for (size_t i = 0; i < n; ++i) {
			buf[i] = (uint8_t)0x00;
		}
		return n;
	}
	return real_syscall(number, a0, a1, a2, a3, a4, a5);
}

uint32_t arc4random(void) {
	if (!real_arc4random) {
		real_arc4random = dlsym(RTLD_NEXT, "arc4random");
	}

	fprintf(stderr, "called arc4random\n");
	return 0;
}

uint32_t arc4random_uniform(uint32_t upper_bound) {
	if (!real_arc4random_uniform) {
		real_arc4random_uniform = dlsym(RTLD_NEXT, "arc4random_uniform");
	}

	fprintf(stderr, "called arc4random_uniform(%u)\n", upper_bound);
	return 0;
}

void arc4random_buf(void *buf, size_t n) {
	if (!real_arc4random_buf) {
		real_arc4random_buf = dlsym(RTLD_NEXT, "arc4random_buf");
	}

	fprintf(stderr, "called arc4random_buf(%p, %lu)\n", buf, n);
	uint8_t *buffer = (uint8_t*)buf;
	for (size_t i = 0; i < n; ++i) {
		buffer[i] = (uint8_t)0x00;
	}
}


void __attribute__((destructor)) dealloc() {
	if (random_fds != NULL) {
		free(random_fds);
	}
	if (random_files != NULL) {
		free(random_files);
	}
}
