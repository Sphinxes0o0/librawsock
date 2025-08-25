/**
 * 简单测试程序 - 验证单头文件库是否能正常编译
 */

#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"

#include <stdio.h>

int main(void) {
    printf("RawSock Library Version: %s\n", rawsock_get_version());
    
    // 测试权限检查
    if (rawsock_check_privileges()) {
        printf("Has raw socket privileges: YES\n");
    } else {
        printf("Has raw socket privileges: NO (need root)\n");
    }
    
    // 测试地址转换
    const char* test_ip = "192.168.1.1";
    uint32_t ip_bin;
    char ip_str[46];
    
    if (rawsock_addr_str_to_bin(test_ip, RAWSOCK_IPV4, &ip_bin) == RAWSOCK_SUCCESS) {
        printf("String to binary conversion: OK\n");
        
        if (rawsock_addr_bin_to_str(&ip_bin, RAWSOCK_IPV4, ip_str) == RAWSOCK_SUCCESS) {
            printf("Binary to string conversion: OK (%s)\n", ip_str);
        }
    }
    
    // 测试校验和计算
    uint8_t test_data[] = {0x45, 0x00, 0x00, 0x20};
    uint16_t checksum = rawsock_calculate_ip_checksum(test_data, sizeof(test_data));
    printf("Checksum calculation: 0x%04x\n", checksum);
    
    printf("\nLibrary compiled successfully!\n");
    return 0;
}