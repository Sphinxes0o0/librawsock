/**
 * @file simple_test.c
 * @brief Very simple test of easy API
 */

#define RAWSOCK_EASY_IMPLEMENTATION
#include "../rawsock_easy.h"
#include <stdio.h>

int main() {
    printf("Testing easy API...\n");
    
    /* Check privileges */
    int priv = easy_check_privileges();
    printf("Has privileges: %s\n", priv ? "Yes" : "No");
    
    /* Get error string */
    const char* err = easy_error_string(EASY_ERROR_PERMISSION);
    printf("Error string test: %s\n", err);
    
    printf("Test completed.\n");
    return 0;
}