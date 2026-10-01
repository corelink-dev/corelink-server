#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef ISSUE_1700_CLOCK_SHIM
#include <sys/time.h>
#include <sys/types.h>

#ifndef ISSUE_1700_CLOCK_NOW
#define ISSUE_1700_CLOCK_NOW 1790856120
#endif
static const time_t oracle_now_seconds = ISSUE_1700_CLOCK_NOW;

int clock_gettime(clockid_t clock_id, struct timespec *value) {
    if (clock_id == CLOCK_REALTIME) {
        value->tv_sec = oracle_now_seconds;
        value->tv_nsec = 0;
        return 0;
    }
    return (int)syscall(SYS_clock_gettime, clock_id, value);
}

time_t time(time_t *value) {
    if (value != NULL) *value = oracle_now_seconds;
    return oracle_now_seconds;
}

int gettimeofday(struct timeval *value, void *timezone) {
    (void)timezone;
    value->tv_sec = oracle_now_seconds;
    value->tv_usec = 0;
    return 0;
}
#else

#include <errno.h>
#include <sys/stat.h>

static int write_all(int fd, const char *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        offset += (size_t)written;
    }
    return 0;
}

static void block_forever(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    for (;;) pause();
}

int main(void) {
    const char *path = "/oracle/started";
    const char *temporary_path = "/oracle/started.tmp";
    pid_t child = fork();
    if (child < 0) return 91;
    if (child == 0) block_forever();

    int fd = open(temporary_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) return 92;
    if (fchmod(fd, 0644) != 0) return 93;
    char line[128];
    int n = snprintf(line, sizeof(line), "pid=%ld ppid=%ld child=%ld nspid=", (long)getpid(), (long)getppid(), (long)child);
    if (n < 0 || (size_t)n >= sizeof(line) || write_all(fd, line, (size_t)n) != 0) return 94;
    int proc = open("/proc/self/status", O_RDONLY);
    if (proc >= 0) {
        char status[4096];
        ssize_t got = read(proc, status, sizeof(status) - 1);
        close(proc);
        if (got > 0) {
            status[got] = '\0';
            char *at = strstr(status, "NSpid:");
            if (at != NULL) {
                at += strlen("NSpid:");
                while (*at == ' ' || *at == '\t') at++;
                char *end = strchr(at, '\n');
                if (end != NULL && write_all(fd, at, (size_t)(end - at)) != 0) return 95;
            }
        }
    }
    if (write_all(fd, "\n", 1) != 0) return 96;
    proc = open("/proc/1/cmdline", O_RDONLY);
    if (proc >= 0) {
        char cmdline[2048];
        ssize_t got = read(proc, cmdline, sizeof(cmdline));
        close(proc);
        if (got > 0) {
            if (write_all(fd, "pid1=", 5) != 0) return 97;
            for (ssize_t i = 0; i < got; i++) {
                char c = cmdline[i] == '\0' ? ' ' : cmdline[i];
                if (write_all(fd, &c, 1) != 0) return 98;
            }
            if (write_all(fd, "\n", 1) != 0) return 99;
        }
    }
    if (close(fd) != 0) return 100;
    if (rename(temporary_path, path) != 0) return 101;
    block_forever();
}
#endif
