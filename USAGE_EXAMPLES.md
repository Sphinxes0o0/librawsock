# 简化接口使用示例

本文档展示了如何使用新的简化接口 `rawsock_easy.h` 进行网络数据包的捕获和发送。

## 1. 基本概念

新的简化接口设计原则：
- **最少参数**：只需要传入必要的参数
- **自动处理**：自动构建包头、计算校验和
- **直观命名**：函数名称清晰表达功能

## 2. 抓包示例

### 2.1 最简单的抓包

```c
#define RAWSOCK_EASY_IMPLEMENTATION
#include "rawsock_easy.h"

int main() {
    // 抓取所有协议的包
    easy_capture_t* cap = easy_capture_start(NULL, PROTO_ALL);
    
    uint8_t buffer[65535];
    int bytes = easy_capture_next(cap, buffer, sizeof(buffer), NULL);
    
    if (bytes > 0) {
        printf("抓到 %d 字节的数据包\n", bytes);
    }
    
    easy_capture_stop(cap);
    return 0;
}
```

### 2.2 指定网卡和协议抓包

```c
// 只在 eth0 上抓取 TCP 包
easy_capture_t* cap = easy_capture_start("eth0", PROTO_TCP);

uint8_t buffer[65535];
easy_packet_info_t info;

// 抓取并获取详细信息
int bytes = easy_capture_next(cap, buffer, sizeof(buffer), &info);

if (bytes > 0) {
    printf("TCP包: %s:%u -> %s:%u\n", 
           info.src_ip, info.src_port,
           info.dst_ip, info.dst_port);
}
```

### 2.3 带超时的抓包

```c
// 等待最多 1 秒抓取一个包
int bytes = easy_capture_next_timeout(cap, buffer, sizeof(buffer), 
                                      1000, &info);

if (bytes == EASY_ERROR_TIMEOUT) {
    printf("超时，没有抓到包\n");
}
```

## 3. 发包示例

### 3.1 发送 UDP 数据包

```c
// 最简单的 UDP 发送
const char* data = "Hello, World!";
int sent = easy_send(NULL,                    // 使用默认网卡
                     "192.168.1.100",         // 目标 IP
                     8080,                     // 目标端口
                     data, strlen(data),       // 数据
                     PROTO_UDP);               // 协议

if (sent > 0) {
    printf("成功发送 %d 字节\n", sent);
}
```

### 3.2 指定网卡发送

```c
// 通过指定网卡发送
int sent = easy_send("eth0",                  // 指定网卡
                     "10.0.0.1", 
                     80,
                     "GET / HTTP/1.0\r\n\r\n", 
                     18,
                     PROTO_TCP);
```

### 3.3 指定源端口发送

```c
// 指定源端口发送 UDP
int sent = easy_send_from("eth0",
                          "192.168.1.100",     // 目标 IP
                          8080,                 // 目标端口
                          12345,                // 源端口
                          data, len,
                          PROTO_UDP);
```

### 3.4 发送 ICMP (Ping)

```c
// 发送 ping
int sent = easy_send_icmp("eth0", "8.8.8.8", NULL, 0);

// 带自定义数据的 ping
const char* ping_data = "Custom ping payload";
int sent = easy_send_icmp("eth0", "8.8.8.8", 
                          ping_data, strlen(ping_data));
```

## 4. 完整示例

### 4.1 简单的端口扫描器

```c
#define RAWSOCK_EASY_IMPLEMENTATION
#include "rawsock_easy.h"
#include <stdio.h>

void scan_port(const char* target_ip, uint16_t port) {
    // 发送 TCP SYN 包
    int sent = easy_send(NULL, target_ip, port, NULL, 0, PROTO_TCP);
    
    if (sent > 0) {
        printf("扫描端口 %u...\n", port);
        
        // 等待响应
        easy_capture_t* cap = easy_capture_start(NULL, PROTO_TCP);
        uint8_t buffer[65535];
        easy_packet_info_t info;
        
        int bytes = easy_capture_next_timeout(cap, buffer, 
                                             sizeof(buffer), 
                                             1000, &info);
        
        if (bytes > 0 && info.src_port == port) {
            printf("端口 %u 开放\n", port);
        } else {
            printf("端口 %u 关闭或无响应\n", port);
        }
        
        easy_capture_stop(cap);
    }
}

int main() {
    if (!easy_check_privileges()) {
        printf("需要 root 权限\n");
        return 1;
    }
    
    // 扫描常用端口
    scan_port("127.0.0.1", 22);   // SSH
    scan_port("127.0.0.1", 80);   // HTTP
    scan_port("127.0.0.1", 443);  // HTTPS
    
    return 0;
}
```

### 4.2 简单的网络监视器

```c
#define RAWSOCK_EASY_IMPLEMENTATION
#include "rawsock_easy.h"
#include <stdio.h>
#include <signal.h>

static int running = 1;

void stop_handler(int sig) {
    running = 0;
}

int main() {
    if (!easy_check_privileges()) {
        printf("需要 root 权限\n");
        return 1;
    }
    
    signal(SIGINT, stop_handler);
    
    // 监视所有 TCP 和 UDP 流量
    easy_capture_t* tcp_cap = easy_capture_start(NULL, PROTO_TCP);
    easy_capture_t* udp_cap = easy_capture_start(NULL, PROTO_UDP);
    
    uint8_t buffer[65535];
    easy_packet_info_t info;
    
    printf("监视网络流量 (Ctrl+C 停止)...\n\n");
    
    while (running) {
        // 检查 TCP
        int bytes = easy_capture_next_timeout(tcp_cap, buffer, 
                                             sizeof(buffer), 
                                             100, &info);
        if (bytes > 0) {
            printf("[TCP] %s:%u -> %s:%u (%zu bytes)\n",
                   info.src_ip, info.src_port,
                   info.dst_ip, info.dst_port,
                   info.packet_size);
        }
        
        // 检查 UDP
        bytes = easy_capture_next_timeout(udp_cap, buffer, 
                                         sizeof(buffer), 
                                         100, &info);
        if (bytes > 0) {
            printf("[UDP] %s:%u -> %s:%u (%zu bytes)\n",
                   info.src_ip, info.src_port,
                   info.dst_ip, info.dst_port,
                   info.packet_size);
        }
    }
    
    easy_capture_stop(tcp_cap);
    easy_capture_stop(udp_cap);
    
    return 0;
}
```

### 4.3 自定义协议发送

```c
// 发送自定义协议的原始数据包
uint8_t raw_packet[100];
struct iphdr* ip = (struct iphdr*)raw_packet;

// 构建 IP 头
ip->version = 4;
ip->ihl = 5;
ip->protocol = 99;  // 自定义协议号
ip->saddr = inet_addr("10.0.0.1");
ip->daddr = inet_addr("10.0.0.2");
// ... 设置其他字段 ...

// 添加自定义数据
memcpy(raw_packet + 20, "CUSTOM_PROTOCOL_DATA", 20);

// 发送原始包
int sent = easy_send_raw("eth0", raw_packet, 40);
```

## 5. 错误处理

```c
int result = easy_send("eth0", "192.168.1.1", 80, data, len, PROTO_TCP);

if (result < 0) {
    // 获取错误描述
    const char* error_msg = easy_error_string(result);
    fprintf(stderr, "发送失败: %s\n", error_msg);
    
    // 根据错误码处理
    switch(result) {
        case EASY_ERROR_PERMISSION:
            printf("请使用 sudo 运行\n");
            break;
        case EASY_ERROR_INTERFACE:
            printf("网卡不存在\n");
            break;
        case EASY_ERROR_INVALID_PARAM:
            printf("参数错误\n");
            break;
        default:
            printf("未知错误\n");
    }
}
```

## 6. 性能优化建议

1. **缓冲区复用**：预分配缓冲区，避免频繁分配
```c
uint8_t* buffer = malloc(65535);
// 使用同一个缓冲区进行多次捕获
```

2. **批量处理**：一次捕获多个包再处理
```c
for (int i = 0; i < 100; i++) {
    packets[i] = easy_capture_next(cap, buffers[i], size, NULL);
}
// 批量处理捕获的包
```

3. **协议过滤**：只捕获需要的协议，减少处理量
```c
// 只捕获 TCP，而不是 PROTO_ALL
easy_capture_t* cap = easy_capture_start("eth0", PROTO_TCP);
```

## 7. 注意事项

1. **权限要求**
   - 所有操作都需要 root 权限
   - 使用 `easy_check_privileges()` 检查

2. **网卡选择**
   - 传 NULL 使用默认网卡
   - 使用 `easy_list_interfaces()` 列出可用网卡

3. **缓冲区大小**
   - 建议使用 65535 字节（最大 IP 包大小）
   - 小缓冲区可能导致 `EASY_ERROR_BUFFER_TOO_SMALL`

4. **协议常量**
   - 使用预定义的 `PROTO_*` 常量
   - `PROTO_ALL` (0) 捕获所有协议

5. **错误处理**
   - 检查所有返回值
   - 使用 `easy_error_string()` 获取错误描述

## 8. 编译和运行

```bash
# 编译
gcc -o myapp myapp.c

# 运行（需要 root）
sudo ./myapp

# 或者设置能力（不需要每次 sudo）
sudo setcap cap_net_raw+ep ./myapp
./myapp
```

## 9. 调试技巧

1. **打印详细信息**
```c
if (bytes > 0) {
    printf("Timestamp: %lu ms\n", info.timestamp_ms);
    printf("Protocol: %u\n", info.protocol);
    printf("Size: %zu bytes\n", info.packet_size);
    // 打印原始数据
    for (int i = 0; i < 20; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}
```

2. **检查网卡状态**
```c
char interfaces[10][32];
int count = easy_list_interfaces(interfaces, 10);
printf("可用网卡:\n");
for (int i = 0; i < count; i++) {
    printf("  - %s\n", interfaces[i]);
}
```

3. **验证权限**
```c
if (!easy_check_privileges()) {
    fprintf(stderr, "错误: 需要 root 权限\n");
    fprintf(stderr, "请运行: sudo %s\n", argv[0]);
    exit(1);
}
```