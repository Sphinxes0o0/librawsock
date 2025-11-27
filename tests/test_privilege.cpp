/**
 * @file test_privilege.cpp
 * @brief Simple test to check if the library can be used without privileges
 */

#include <rawsock/rawsock.hpp>
#include <rawsock/rawsock_c.h>
#include <cstdio>

int main() {
    printf("=== Privilege Test ===\n\n");
    
    // Test C++ interface
    printf("C++ privilege check: ");
    bool cpp_privileges = rawsock::capture::check_privileges();
    printf("%s\n", cpp_privileges ? "HAS PRIVILEGES" : "NO PRIVILEGES");
    
    // Test C interface
    printf("C privilege check: ");
    int c_privileges = rawsock_check_privileges();
    printf("%s\n", c_privileges ? "HAS PRIVILEGES" : "NO PRIVILEGES");
    
    // Try to create a capture
    printf("\nAttempting to create capture...\n");
    rawsock::capture cap;
    rawsock::capture_config config;
    config.interface_name = "lo";
    config.recv_timeout_ms = 100;
    
    rawsock::error_code ec = cap.open(config);
    
    if (ec == rawsock::error_code::success) {
        printf("Capture opened successfully (running as root or with capabilities)\n");
        cap.close();
    } else if (ec == rawsock::error_code::permission_denied) {
        printf("Permission denied (expected when not running as root)\n");
    } else {
        printf("Error: %s\n", rawsock::error_category().message(static_cast<int>(ec)).c_str());
    }
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
