/*
 * smoke checks libarc through arc.h alone, as an app links it: version and
 * key generation, a rejected start that closes its descriptor, and, run
 * as root, a tunnel on a real utun that logs, stops, and goes quiet.
 *
 * cc -I cmd/libarc/include smoke.c libarc.a -framework CoreFoundation -framework Security -lresolv
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <time.h>
#include <unistd.h>

#include "arc.h"

static int failures;

#define CHECK(cond, ...)                                       \
	do {                                                       \
		if (!(cond)) {                                         \
			fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
			fprintf(stderr, __VA_ARGS__);                      \
			fputc('\n', stderr);                               \
			failures++;                                        \
		}                                                      \
	} while (0)

static int fd_open(int fd) { return fcntl(fd, F_GETFD) != -1 || errno != EBADF; }

/* json_string copies the string member name of json into out. */
static int json_string(const char *json, const char *name, char *out, size_t n) {
	char key[64];
	snprintf(key, sizeof key, "\"%s\":\"", name);
	const char *p = strstr(json, key);
	if (!p) return 0;
	p += strlen(key);
	const char *end = strchr(p, '"');
	if (!end || (size_t)(end - p) >= n) return 0;
	memcpy(out, p, end - p);
	out[end - p] = 0;
	return 1;
}

struct recorder {
	pthread_mutex_t mu;
	pthread_cond_t cond;
	int events, starting, stopped, after_stop;
	int stop_returned;
	char last[512];
};

static int on_event(void *context, const char *event_json) {
	struct recorder *r = context;
	pthread_mutex_lock(&r->mu);
	r->events++;
	if (r->stop_returned) r->after_stop++;
	if (strstr(event_json, "\"msg\":\"starting\"")) r->starting = 1;
	if (strstr(event_json, "\"event\":\"stopped\"")) r->stopped = 1;
	snprintf(r->last, sizeof r->last, "%s", event_json);
	pthread_cond_broadcast(&r->cond);
	pthread_mutex_unlock(&r->mu);
	return 0;
}

/* utun_open creates a utun, as a packet tunnel provider's would be. */
static int utun_open(void) {
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0) return -1;
	struct ctl_info info = {0};
	strlcpy(info.ctl_name, "com.apple.net.utun_control", sizeof info.ctl_name);
	struct sockaddr_ctl addr = {0};
	if (ioctl(fd, CTLIOCGINFO, &info) < 0) goto fail;
	addr.sc_len = sizeof addr;
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	addr.sc_id = info.ctl_id;
	addr.sc_unit = 0; /* the next free utun */
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) goto fail;
	return fd;
fail:
	close(fd);
	return -1;
}

static void tunnel_on_utun(const char *priv, const char *pub) {
	int fd = utun_open();
	if (fd < 0) {
		printf("skip: no utun (%s); run as root for the tunnel check\n", strerror(errno));
		return;
	}
	/* Nothing answers at the relay address: the tunnel starts, keeps
	 * trying to reach it, and must still stop promptly. */
	char config[512];
	snprintf(config, sizeof config,
	         "{\"relay\":\"127.0.0.1:9\",\"relay_key\":\"%s\",\"token\":\"t\",\"private_key\":\"%s\"}", pub, priv);
	struct recorder r = {.mu = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
	int64_t h = 0;
	char *err = arc_start(config, fd, on_event, &r, &h);
	CHECK(err == NULL, "arc_start on a utun: %s", err);
	if (err) {
		arc_free(err);
		return;
	}
	struct timespec deadline;
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 5;
	pthread_mutex_lock(&r.mu);
	while (!r.starting && pthread_cond_timedwait(&r.cond, &r.mu, &deadline) == 0) {
	}
	CHECK(r.starting, "no \"starting\" log event within 5 s");
	pthread_mutex_unlock(&r.mu);

	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	arc_stop(h);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	CHECK(secs < 2, "arc_stop took %.1f s", secs);
	pthread_mutex_lock(&r.mu);
	r.stop_returned = 1;
	CHECK(r.stopped, "no stopped event before arc_stop returned");
	CHECK(strstr(r.last, "\"event\":\"stopped\"") && !strstr(r.last, "\"error\""),
	      "last event %s, want a stopped event without an error", r.last);
	pthread_mutex_unlock(&r.mu);
	usleep(200 * 1000);
	pthread_mutex_lock(&r.mu);
	CHECK(r.after_stop == 0, "%d events after arc_stop returned", r.after_stop);
	pthread_mutex_unlock(&r.mu);
	CHECK(!fd_open(fd), "utun descriptor still open after arc_stop");
	arc_stop(h); /* a freed handle is ignored */
	printf("ok: tunnel on a utun started, logged %d events, and stopped in %.2f s\n", r.events, secs);
}

int main(void) {
	char *v = arc_version();
	CHECK(v && *v, "arc_version is empty");
	printf("version: %s\n", v ? v : "(null)");
	arc_free(v);

	char *key = arc_generate_key();
	char priv[64], pub[64];
	CHECK(key && json_string(key, "private_key", priv, sizeof priv) && json_string(key, "public_key", pub, sizeof pub),
	      "arc_generate_key: %s", key ? key : "(null)");
	CHECK(strlen(priv) == 44 && strlen(pub) == 44 && strcmp(priv, pub) != 0, "keys are not two 32-byte base64 values: %s", key);
	arc_free(key);

	/* A rejected start reports why and closes the descriptor it was given. */
	int p[2];
	CHECK(pipe(p) == 0, "pipe");
	struct recorder r = {.mu = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
	int64_t h = -1;
	char *err = arc_start("{\"relay\":\"nope\"}", p[0], on_event, &r, &h);
	CHECK(err != NULL, "arc_start accepted a bad config and a pipe");
	if (err) printf("rejected as expected: %s\n", err);
	arc_free(err);
	CHECK(h == -1, "handle set by a failed arc_start");
	CHECK(!fd_open(p[0]), "descriptor left open by a failed arc_start");
	CHECK(r.events == 0, "%d events from a failed arc_start", r.events);
	close(p[1]);
	arc_free(NULL);

	tunnel_on_utun(priv, pub);

	if (failures) {
		fprintf(stderr, "libarc smoke: %d check(s) failed\n", failures);
		return 1;
	}
	printf("libarc smoke: all checks passed\n");
	return 0;
}
