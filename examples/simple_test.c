#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.h"
#include <stdio.h>

int main(void) {
    printf("Testing rawsock library...\n");

    if (!rawsock_has_caps()) {
        printf("Insufficient privileges for raw socket operations (skip privileged checks)\n");
        return 0;
    }
    printf("Privileges OK\n");

    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    cfg.protocol = 0;

    RAWSOCK_AUTO_CLOSE rawsock_t* sock = rawsock_open(&cfg);
    if (!sock) {
        printf("Failed to create raw socket: %s\n",
               rawsock_strerror(rawsock_last_err(NULL)));
        return 1;
    }
    printf("Successfully created raw socket\n");

    rawsock_close(sock);
    sock = NULL;

    cfg.protocol = IPPROTO_ICMP;
    sock = rawsock_open(&cfg);
    if (!sock) {
        printf("Failed to create ICMP raw socket: %s\n",
               rawsock_strerror(rawsock_last_err(NULL)));
        return 1;
    }
    printf("Successfully created ICMP raw socket\n");

    printf("All tests passed!\n");
    return 0;
}
