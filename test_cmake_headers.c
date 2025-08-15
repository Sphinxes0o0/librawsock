#include <stdio.h>
#include <stdlib.h>

#include "rawsock.h"
#include "packet.h"

int main() {
    printf("Testing CMake-copied headers...\n");
    
    // Test version from config.h
    printf("Config version: %s\n", RAWSOCK_VERSION_STRING);
    
    // Test library version
    printf("Library version: %s\n", rawsock_get_version());
    
    // Test privilege check
    if (rawsock_check_privileges()) {
        printf("Raw socket privileges: OK\n");
    } else {
        printf("Raw socket privileges: NOT AVAILABLE (run with sudo)\n");
    }
    
    printf("CMake-copied headers working correctly!\n");
    return 0;
}
