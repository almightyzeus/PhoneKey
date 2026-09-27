/*
 * Test harness (never installed): runs the "auth" stack of SERVICE from a
 * private CONFDIR via pam_start_confdir, so /etc/pam.d is never read.
 * Prints the conversation and the result; answers no prompts.
 *
 *   pam_harness CONFDIR SERVICE USER
 * Exit status: 0 success, 1 failure, 2 usage/setup error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
    (void)data;
    struct pam_response *r = calloc((size_t)n, sizeof(*r));
    if (r == NULL)
        return PAM_BUF_ERR;
    for (int i = 0; i < n; i++) {
        switch (msg[i]->msg_style) {
        case PAM_TEXT_INFO:
            printf("info: %s\n", msg[i]->msg);
            break;
        case PAM_ERROR_MSG:
            printf("error: %s\n", msg[i]->msg);
            break;
        default:
            printf("prompt: %s\n", msg[i]->msg);
            free(r);
            return PAM_CONV_ERR; /* no password here */
        }
    }
    fflush(stdout);
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s CONFDIR SERVICE USER\n", argv[0]);
        return 2;
    }
    struct pam_conv c = {conv, NULL};
    pam_handle_t *pamh = NULL;
    int r = pam_start_confdir(argv[2], argv[3], &c, argv[1], &pamh);
    if (r != PAM_SUCCESS) {
        fprintf(stderr, "pam_start_confdir: %d\n", r);
        return 2;
    }
    r = pam_authenticate(pamh, 0);
    printf("result: %s\n", r == PAM_SUCCESS ? "PAM_SUCCESS" : pam_strerror(pamh, r));
    pam_end(pamh, r);
    return r == PAM_SUCCESS ? 0 : 1;
}
