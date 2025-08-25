# RawSock - 轻量级单头文件 Raw Socket 库

一个简洁的单头文件 C 语言原始套接字库，支持 Linux 和 macOS 平台。

## 特性

- **单头文件** - 只需包含 `rawsock.h` 即可使用
- **跨平台支持** - 支持 Linux 和 macOS
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

### 完整示例

查看 `example.c` 获取更多使用示例。

## API 参考

### 核心函数

| 函数 | 描述 |
|------|------|
| `rawsock_create()` | 创建原始套接字 |
| `rawsock_create_with_config()` | 使用自定义配置创建套接字 |
| `rawsock_destroy()` | 关闭并释放套接字 |
| `rawsock_send()` | 发送数据包 |
| `rawsock_recv()` | 接收数据包 |

### 数据包解析

| 函数 | 描述 |
|------|------|
| `rawsock_parse_ipv4_header()` | 解析 IPv4 头部 |
| `rawsock_parse_tcp_header()` | 解析 TCP 头部 |
| `rawsock_parse_udp_header()` | 解析 UDP 头部 |
| `rawsock_parse_icmp_header()` | 解析 ICMP 头部 |

### 工具函数

| 函数 | 描述 |
|------|------|
| `rawsock_calculate_ip_checksum()` | 计算 IP 校验和 |
| `rawsock_calculate_transport_checksum()` | 计算 TCP/UDP 校验和 |
| `rawsock_addr_str_to_bin()` | IP 字符串转二进制 |
| `rawsock_addr_bin_to_str()` | 二进制转 IP 字符串 |

## 文件结构

```
.
├── rawsock.h              # 单头文件库
├── example.c              # 使用示例
├── test_single_header.c   # 测试程序
├── README.md              # 本文档
└── README_SINGLE_HEADER.md # 英文文档
```

## 平台说明

### Linux
- 需要 root 权限或 CAP_NET_RAW 能力
- 完整支持所有功能

### macOS
- 需要 root 权限
- 由于 BSD 实现，某些原始套接字行为可能有限制
- IP_HDRINCL 选项行为可能与 Linux 不同

## 错误处理

所有函数使用 `rawsock_error_t` 枚举返回错误码：

```c
rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
if (!sock) {
    // 套接字创建失败
}

int sent = rawsock_send(sock, packet, size, "192.168.1.1");
if (sent < 0) {
    rawsock_error_t error = rawsock_get_last_error(sock);
    printf("错误: %s\n", rawsock_error_string(error));
}
```

## 编译选项

基础编译：
```bash
gcc -o program program.c
```

优化编译：
```bash
gcc -O2 -o program program.c
```

调试编译：
```bash
gcc -g -Wall -Wextra -o program program.c
```

## 测试

运行测试程序：

```bash
# 编译测试程序
gcc -o test test_single_header.c

# 运行测试（部分测试需要 root）
./test           # 运行非特权测试
sudo ./test      # 运行所有测试
```

## 版本

当前版本：1.0.0

## 作者

Sphinxes0o0

## 许可

这是原始 librawsock 库的简化单头文件版本。