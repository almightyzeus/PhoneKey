/*
 * pam_phonekey — asks phonekeyd to authenticate the user with their phone.
 *
 * A thin client, no cryptography: phonekeyd creates the challenge and checks
 * the phone's signature (protocol/PROTOCOL.md, SECURITY.md §4). This module
 * only talks to the daemon's Unix socket, after checking with SO_PEERCRED that
 * the socket belongs to the daemon's user.
 *
 * Every failure path returns quickly and never PAM_SUCCESS. It is meant to be
 * configured as `auth sufficient`, so the password prompt that follows in the
 * stack always stays available:
 *
 *   daemon approved        -> PAM_SUCCESS
 *   denied on the phone    -> PAM_AUTH_ERR          (password prompt follows)
 *   anything else          -> PAM_AUTHINFO_UNAVAIL  (password prompt follows)
 *
 * Module arguments:
 *   action=sudo|unlock|login   required; what the phone shows
 *   timeout=N                  seconds to wait for the phone (default 35, max 120)
 *   socket=PATH                default /run/phonekey/phonekey.sock
 *   daemon_user=NAME           default phonekey
 *   debug                      log more to syslog (authpriv)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PAM_SM_AUTH
#include <security/pam_ext.h>
#include <security/pam_modules.h>

/* Built with -fvisibility=hidden: only the PAM entry points are exported. */
#define EXPORT PAM_EXTERN __attribute__((visibility("default")))

#define DEFAULT_SOCKET "/run/phonekey/phonekey.sock"
#define DEFAULT_DAEMON_USER "phonekey"
#define DEFAULT_TIMEOUT 35
#define MAX_TIMEOUT 120
#define MAX_REPLY 4096
#define MAX_NAME 64

struct options {
    const char *action;
    const char *socket_path;
    const char *daemon_user;
    int timeout;
    int debug;
};

static int parse_options(pam_handle_t *pamh, int argc, const char **argv, struct options *opt)
{
    opt->action = NULL;
    opt->socket_path = DEFAULT_SOCKET;
    opt->daemon_user = DEFAULT_DAEMON_USER;
    opt->timeout = DEFAULT_TIMEOUT;
    opt->debug = 0;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "action=", 7) == 0) {
            opt->action = argv[i] + 7;
        } else if (strncmp(argv[i], "timeout=", 8) == 0) {
            char *end;
            long t = strtol(argv[i] + 8, &end, 10);
            if (*end != '\0' || t < 1 || t > MAX_TIMEOUT) {
                pam_syslog(pamh, LOG_ERR, "invalid %s", argv[i]);
                return -1;
            }
            opt->timeout = (int)t;
        } else if (strncmp(argv[i], "socket=", 7) == 0) {
            opt->socket_path = argv[i] + 7;
        } else if (strncmp(argv[i], "daemon_user=", 12) == 0) {
            opt->daemon_user = argv[i] + 12;
        } else if (strcmp(argv[i], "debug") == 0) {
            opt->debug = 1;
        } else {
            pam_syslog(pamh, LOG_ERR, "unknown option %s", argv[i]);
            return -1;
        }
    }
    if (opt->action == NULL || (strcmp(opt->action, "sudo") != 0 && strcmp(opt->action, "unlock") != 0 &&
                                strcmp(opt->action, "login") != 0 && strcmp(opt->action, "test") != 0)) {
        pam_syslog(pamh, LOG_ERR, "action=sudo|unlock|login is required");
        return -1;
    }
    return 0;
}

/* User names are embedded in JSON unescaped, so allow only a safe subset. */
static int valid_user(const char *user)
{
    size_t n = strlen(user);
    if (n == 0 || n > MAX_NAME || user[0] == '-')
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = user[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static long remaining_ms(const struct timespec *deadline)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (deadline->tv_sec - now.tv_sec) * 1000L + (deadline->tv_nsec - now.tv_nsec) / 1000000L;
}

/* Connects and checks that the listening process runs as the daemon user. */
static int connect_daemon(pam_handle_t *pamh, const struct options *opt)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    if (strlen(opt->socket_path) >= sizeof(addr.sun_path))
        return -1;
    strcpy(addr.sun_path, opt->socket_path);

    struct passwd pwbuf, *pw = NULL;
    char buf[1024];
    if (getpwnam_r(opt->daemon_user, &pwbuf, buf, sizeof(buf), &pw) != 0 || pw == NULL) {
        if (opt->debug)
            pam_syslog(pamh, LOG_DEBUG, "daemon user %s does not exist", opt->daemon_user);
        return -1;
    }
    uid_t daemon_uid = pw->pw_uid;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct timeval tv = {.tv_sec = 2};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (opt->debug)
            pam_syslog(pamh, LOG_DEBUG, "phonekeyd not reachable: %m");
        close(fd);
        return -1;
    }
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 || len != sizeof(cred) ||
        cred.uid != daemon_uid) {
        pam_syslog(pamh, LOG_WARNING, "%s is not owned by %s; ignoring it", opt->socket_path, opt->daemon_user);
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const char *data, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

/*
 * Copies the string value of "key" in a one-line JSON object written by
 * phonekeyd (json.dumps: `"key": "value"`). Returns 0 if found.
 */
static int json_string(const char *line, const char *key, char *out, size_t out_len)
{
    char pattern[32];
    int n = snprintf(pattern, sizeof(pattern), "\"%s\": \"", key);
    if (n < 0 || (size_t)n >= sizeof(pattern))
        return -1;
    const char *p = strstr(line, pattern);
    if (p == NULL)
        return -1;
    p += n;
    size_t i = 0;
    while (p[i] != '"' && p[i] != '\0' && p[i] != '\\') {
        if (i + 1 >= out_len)
            return -1;
        out[i] = p[i];
        i++;
    }
    if (p[i] != '"')
        return -1;
    out[i] = '\0';
    return 0;
}

static void info(pam_handle_t *pamh, int flags, const char *message)
{
    if (!(flags & PAM_SILENT))
        pam_info(pamh, "%s", message);
}

EXPORT int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct options opt;
    if (parse_options(pamh, argc, argv, &opt) != 0)
        return PAM_AUTHINFO_UNAVAIL;

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || !valid_user(user))
        return PAM_USER_UNKNOWN;

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += opt.timeout;

    int fd = connect_daemon(pamh, &opt);
    if (fd < 0)
        return PAM_AUTHINFO_UNAVAIL;

    char request[256];
    int len = snprintf(request, sizeof(request), "{\"op\": \"auth\", \"action\": \"%s\", \"account\": \"%s\"}\n",
                       opt.action, user);
    if (len < 0 || (size_t)len >= sizeof(request) || send_all(fd, request, (size_t)len) != 0) {
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }

    int ret = PAM_AUTHINFO_UNAVAIL;
    char reply[MAX_REPLY + 1];
    size_t used = 0;
    for (;;) {
        long wait = remaining_ms(&deadline);
        if (wait <= 0) {
            info(pamh, flags, "PhoneKey: no answer from the phone.");
            break;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int r = poll(&pfd, 1, (int)wait);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            continue; /* timeout: reported at the top of the loop */
        ssize_t n = recv(fd, reply + used, MAX_REPLY - used, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break; /* daemon closed the connection without a result */
        used += (size_t)n;
        reply[used] = '\0';

        int done = 0;
        char *newline;
        while ((newline = memchr(reply, '\n', used)) != NULL) {
            *newline = '\0';
            char value[32];
            if (json_string(reply, "result", value, sizeof(value)) == 0) {
                if (strcmp(value, "ok") == 0) {
                    ret = PAM_SUCCESS;
                } else if (strcmp(value, "denied") == 0) {
                    info(pamh, flags, "PhoneKey: denied on the phone.");
                    ret = PAM_AUTH_ERR;
                } else {
                    char reason[64];
                    if (opt.debug && json_string(reply, "reason", reason, sizeof(reason)) == 0)
                        pam_syslog(pamh, LOG_DEBUG, "phonekeyd: %s (%s)", value, reason);
                }
                done = 1;
                break;
            }
            if (json_string(reply, "event", value, sizeof(value)) == 0 && strcmp(value, "sent") == 0)
                info(pamh, flags, "PhoneKey: approve on your phone, or tap Deny to use your password.");
            size_t consumed = (size_t)(newline - reply) + 1;
            memmove(reply, newline + 1, used - consumed);
            used -= consumed;
            reply[used] = '\0';
        }
        if (done || used >= MAX_REPLY)
            break;
    }
    close(fd);
    if (ret == PAM_SUCCESS)
        pam_syslog(pamh, LOG_INFO, "user %s authenticated with PhoneKey (%s)", user, opt.action);
    else if (opt.debug)
        pam_syslog(pamh, LOG_DEBUG, "PhoneKey did not authenticate %s: %s", user, pam_strerror(pamh, ret));
    return ret;
}

EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
