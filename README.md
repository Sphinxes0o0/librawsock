# RawSock - 轻量级单头文件 Raw Socket 库

一个简洁的单头文件 C 语言原始套接字库，支持 Linux 和 macOS 平台。

## 特性

- **单头文件** - 只需包含 `rawsock.h` 即可使用
- **跨平台支持** - 支持 Linux
- **IPv4/IPv6** - 完整支持两种协议
- **数据包解析** - 内置 IP、TCP、UDP、ICMP 头部解析器
- **校验和计算** - IP 和传输层校验和工具
- **简洁 API** - 直观易用的接口设计
- **零依赖** - 仅使用标准系统库

## 快速开始

### 1. 复制头文件

将 `rawsock.h` 复制到你的项目中。

### 2. 使用库

在一个源文件中定义实现：

```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"
```

在其他源文件中正常包含：

```c
#include "rawsock.h"
```

### 3. 编译运行

```bash
# 编译
gcc -o myprogram myprogram.c

# 运行（需要 root 权限）
sudo ./myprogram
```

## 简化接口 (Easy API)

项目还提供了一个简化版本的 API，封装在 `rawsock_easy.h` 中，使网络编程变得更加简单直观。

### 简化接口特性

- **简单易用**：最少的参数，直观的函数命名
- **协议过滤**：支持按协议类型过滤数据包（TCP、UDP、ICMP等）
- **灵活发送**：支持多种协议的数据包发送
- **网卡指定**：可以指定网卡进行抓包和发包
- **超时控制**：支持带超时的数据包捕获

### 使用简化接口

```c
#define RAWSOCK_EASY_IMPLEMENTATION
#include "rawsock_easy.h"
```

### 简化接口示例

#### 抓包接口

```c
// 开始抓包
easy_capture_t* easy_capture_start(const char* interface, uint8_t protocol);

// 捕获下一个数据包
int easy_capture_next(easy_capture_t* capture, void* buffer, 
                      size_t buffer_size, easy_packet_info_t* info);

// 带超时的捕获
int easy_capture_next_timeout(easy_capture_t* capture, void* buffer,
                               size_t buffer_size, int timeout_ms, 
                               easy_packet_info_t* info);

// 停止抓包
void easy_capture_stop(easy_capture_t* capture);
```

#### 发包接口

```c
// 发送数据包
int easy_send(const char* interface, const char* dest_ip, uint16_t dest_port,
              const void* payload, size_t payload_size, uint8_t protocol);

// 发送 ICMP 包（ping）
int easy_send_icmp(const char* interface, const char* dest_ip,
                   const void* payload, size_t payload_size);

// 发送原始数据包
int easy_send_raw(const char* interface, const void* packet, 
                  size_t packet_size);
```

## 示例代码

### 基础示例

```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"
#include <stdio.h>

int main(void) {
    // 检查权限
    if (!rawsock_check_privileges()) {
        printf("需要 root 权限\n");
        return 1;
    }
    
    // 创建原始套接字
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) {
        printf("创建套接字失败\n");
        return 1;
    }
    
    // 发送数据包
    uint8_t packet[64];
    // ... 构建数据包 ...
    rawsock_send(sock, packet, sizeof(packet), "192.168.1.1");
    
    // 接收数据包
    uint8_t buffer[1024];
    rawsock_packet_info_t info;
    int bytes = rawsock_recv(sock, buffer, sizeof(buffer), &info);
    if (bytes > 0) {
        printf("从 %s 接收了 %d 字节\n", info.src_addr, bytes);
    }
    
    // 清理
    rawsock_destroy(sock);
    return 0;
}
```

### 简化接口示例

```c
#define RAWSOCK_EASY_IMPLEMENTATION
#include "rawsock_easy.h"

int main() {
    // 检查权限
    if (!easy_check_privileges()) {
        printf("需要 root 权限\n");
        return 1;
    }
    
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

## API 参考

### 核心函数

| 函数 | 描述 |
|------|------|
| `rawsock_create()` | 创建原始套接字 |
| `rawsock_create_with_config()` | 使用自定义配置创建套接字 |
| `rawsock_destroy()` | 关闭并释放套接字 |
| `rawsock_send()` | 发送数据包 |

### 协议常量

```c
#define PROTO_ALL      0    // 捕获所有协议
#define PROTO_ICMP     1    // ICMP 协议
#define PROTO_TCP      6    // TCP 协议  
#define PROTO_UDP      17   // UDP 协议
#define PROTO_ICMPV6   58   // ICMPv6 协议
#define PROTO_RAW      255  // 原始 IP
```

### 数据结构

#### 数据包信息
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