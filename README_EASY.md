# Easy Raw Socket API

## 简介

`rawsock_easy.h` 提供了一个简化易用的网络数据包捕获和发送接口，封装了底层的 `rawsock.h` API。这个库的设计目标是让网络编程变得更加简单直观。

## 主要特性

- **简单易用**：最少的参数，直观的函数命名
- **协议过滤**：支持按协议类型过滤数据包（TCP、UDP、ICMP等）
- **灵活发送**：支持多种协议的数据包发送
- **网卡指定**：可以指定网卡进行抓包和发包
- **超时控制**：支持带超时的数据包捕获

## 快速开始

### 编译要求

```bash
# 需要 root 权限运行
# Linux 系统需要 gcc 编译器
```

### 基本使用

```c
#define RAWSOCK_EASY_IMPLEMENTATION
#include "rawsock_easy.h"
```

## API 接口说明

### 1. 抓包接口

#### 开始抓包
```c
easy_capture_t* easy_capture_start(const char* interface, uint8_t protocol);
```
- **interface**: 网卡名称（如 "eth0", "lo"），NULL 表示任意网卡
- **protocol**: 协议类型（PROTO_ALL 抓取所有协议）
- **返回**: 抓包上下文，失败返回 NULL

#### 捕获下一个数据包
```c
int easy_capture_next(easy_capture_t* capture, void* buffer, 
                      size_t buffer_size, easy_packet_info_t* info);
```
- **capture**: 抓包上下文
- **buffer**: 用于存储数据包的缓冲区
- **buffer_size**: 缓冲区大小
- **info**: 可选的数据包信息结构（可以为 NULL）
- **返回**: 捕获的字节数，失败返回负数错误码

#### 带超时的捕获
```c
int easy_capture_next_timeout(easy_capture_t* capture, void* buffer,
                               size_t buffer_size, int timeout_ms, 
                               easy_packet_info_t* info);
```
- **timeout_ms**: 超时时间（毫秒），0 表示不超时
- **返回**: 捕获的字节数，超时返回 EASY_ERROR_TIMEOUT

#### 停止抓包
```c
void easy_capture_stop(easy_capture_t* capture);
```

### 2. 发包接口

#### 发送数据包
```c
int easy_send(const char* interface, const char* dest_ip, uint16_t dest_port,
              const void* payload, size_t payload_size, uint8_t protocol);
```
- **interface**: 发送网卡（NULL 使用默认）
- **dest_ip**: 目标 IP 地址
- **dest_port**: 目标端口（TCP/UDP）
- **payload**: 要发送的数据
- **payload_size**: 数据大小
- **protocol**: 协议类型（PROTO_TCP, PROTO_UDP 等）
- **返回**: 发送的字节数，失败返回负数错误码

#### 指定源端口发送
```c
int easy_send_from(const char* interface, const char* dest_ip, 
                   uint16_t dest_port, uint16_t src_port,
                   const void* payload, size_t payload_size, 
                   uint8_t protocol);
```

#### 发送 ICMP 包（ping）
```c
int easy_send_icmp(const char* interface, const char* dest_ip,
                   const void* payload, size_t payload_size);
```

#### 发送原始数据包
```c
int easy_send_raw(const char* interface, const void* packet, 
                  size_t packet_size);
```
- **packet**: 完整的数据包（包含 IP 头部）

### 3. 工具函数

#### 检查权限
```c
int easy_check_privileges(void);
```
返回 1 表示有足够权限，0 表示没有

#### 列出网络接口
```c
int easy_list_interfaces(char interfaces[][32], int max_interfaces);
```

#### 获取默认网卡
```c
int easy_get_default_interface(char* interface);
```

## 协议常量

```c
#define PROTO_ALL      0    // 捕获所有协议
#define PROTO_ICMP     1    // ICMP 协议
#define PROTO_TCP      6    // TCP 协议  
#define PROTO_UDP      17   // UDP 协议
#define PROTO_ICMPV6   58   // ICMPv6 协议
#define PROTO_RAW      255  // 原始 IP
```

## 数据结构

### 数据包信息
```c
typedef struct {
    char src_ip[46];        // 源 IP 地址
    char dst_ip[46];        // 目标 IP 地址
    uint16_t src_port;      // 源端口
    uint16_t dst_port;      // 目标端口
    uint8_t protocol;       // 协议号
    size_t packet_size;     // 数据包大小
    uint64_t timestamp_ms;  // 时间戳（毫秒）
} easy_packet_info_t;
```

## 使用示例

### 示例 1：简单抓包

```c
#define RAWSOCK_EASY_IMPLEMENTATION
#include "rawsock_easy.h"

int main() {
    // 在 eth0 网卡上抓取所有 TCP 包
    easy_capture_t* cap = easy_capture_start("eth0", PROTO_TCP);
    if (!cap) {
        printf("启动抓包失败\n");
        return 1;
    }
    
    uint8_t buffer[65535];
    easy_packet_info_t info;
    
    // 抓取 10 个包
    for (int i = 0; i < 10; i++) {
        int bytes = easy_capture_next(cap, buffer, sizeof(buffer), &info);
        if (bytes > 0) {
            printf("抓到包: %s:%u -> %s:%u, %zu 字节\n",
                   info.src_ip, info.src_port,
                   info.dst_ip, info.dst_port,
                   info.packet_size);
        }
    }
    
    easy_capture_stop(cap);
    return 0;
}
```

### 示例 2：发送 UDP 数据包

```c
int main() {
    const char* data = "Hello, World!";
    
    // 通过 eth0 发送 UDP 包到 192.168.1.100:8080
    int sent = easy_send("eth0", "192.168.1.100", 8080, 
                        data, strlen(data), PROTO_UDP);
    
    if (sent > 0) {
        printf("成功发送 %d 字节\n", sent);
    } else {
        printf("发送失败: %s\n", easy_error_string(sent));
    }
    
    return 0;
}
```

### 示例 3：发送 ICMP ping

```c
int main() {
    // 发送 ping 到 8.8.8.8
    int sent = easy_send_icmp("eth0", "8.8.8.8", NULL, 0);
    
    if (sent > 0) {
        printf("Ping 发送成功\n");
    }
    
    return 0;
}
```

### 示例 4：带超时的抓包

```c
int main() {
    easy_capture_t* cap = easy_capture_start(NULL, PROTO_ALL);
    
    uint8_t buffer[65535];
    easy_packet_info_t info;
    
    // 等待最多 1 秒抓取一个包
    int bytes = easy_capture_next_timeout(cap, buffer, sizeof(buffer), 
                                          1000, &info);
    
    if (bytes > 0) {
        printf("抓到包\n");
    } else if (bytes == EASY_ERROR_TIMEOUT) {
        printf("超时，没有抓到包\n");
    }
    
    easy_capture_stop(cap);
    return 0;
}
```

## 编译示例程序

```bash
# 编译抓包示例
gcc -o easy_capture examples/easy_capture.c

# 编译发包示例  
gcc -o easy_send examples/easy_send.c

# 编译综合演示
gcc -o easy_demo examples/easy_demo.c

# 运行（需要 root 权限）
sudo ./easy_capture eth0 tcp
sudo ./easy_send udp 192.168.1.100 8080 "Hello"
sudo ./easy_demo
```

## 错误处理

所有函数在失败时返回负数错误码：

```c
typedef enum {
    EASY_SUCCESS = 0,
    EASY_ERROR_INVALID_PARAM = -1,
    EASY_ERROR_PERMISSION = -2,
    EASY_ERROR_SOCKET = -3,
    EASY_ERROR_INTERFACE = -4,
    EASY_ERROR_TIMEOUT = -5,
    EASY_ERROR_BUFFER_TOO_SMALL = -6,
    EASY_ERROR_SEND_FAILED = -7,
    EASY_ERROR_RECV_FAILED = -8,
    EASY_ERROR_UNKNOWN = -9
} easy_error_t;
```

使用 `easy_error_string()` 获取错误描述：

```c
const char* error_msg = easy_error_string(error_code);
printf("错误: %s\n", error_msg);
```

## 注意事项

1. **权限要求**：所有操作都需要 root 权限
2. **缓冲区大小**：建议使用 65535 字节的缓冲区以容纳最大的 IP 包
3. **协议过滤**：使用 PROTO_ALL 可以捕获所有协议的包
4. **网卡指定**：传入 NULL 表示使用默认网卡
5. **线程安全**：每个 capture 上下文应该在单个线程中使用

## 与底层 API 的对比

| 操作 | 底层 rawsock.h | 简化 rawsock_easy.h |
|------|---------------|-------------------|
| 抓包 | 需要创建 socket、配置选项、解析包头 | 一个函数调用 |
| 发包 | 需要构建完整包头、计算校验和 | 自动构建包头 |
| 过滤 | 需要手动过滤 | 内置协议过滤 |
| 错误处理 | 多个错误码 | 简化的错误码 |

## 性能说明

- 简化 API 在底层 API 基础上增加了少量开销
- 自动包头构建和校验和计算会有轻微性能影响
- 适合大多数应用场景，极端性能要求可使用底层 API

## 许可证

MIT License