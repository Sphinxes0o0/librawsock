#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.h"
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("Testing raw socket permissions...\n");

    uid_t euid = geteuid();
    printf("Effective user ID: %d\n", euid);

    if (!rawsock_has_caps()) {
        printf("No raw socket privileges. Run with sudo.\n");
        return 1;
    }
    printf("Raw socket privileges OK\n");

    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    cfg.protocol = IPPROTO_ICMP;

    RAWSOCK_AUTO_CLOSE rawsock_t* sock = rawsock_open(&cfg);
    if (!sock) {
        printf("Failed to create raw socket: %s\n",
               rawsock_strerror(rawsock_last_err(NULL)));
        return 1;
    }
    printf("Successfully created raw socket with rawsock library\n");
    return 0;
}
