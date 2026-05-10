# RawSock — Lightweight Single-Header Raw Socket Library

一个简洁、高效、单头文件的 C 语言原始套接字库。

## 特性

- **单头文件** — 只需 `rawsock.h`，通过 `#define RAWSOCK_IMPLEMENTATION` 引入实现
- **分层 API** — Core / Helpers / Protocol Parsers / High-level，按需使用
- **统一错误处理** — `rawsock_last_err()` + `rawsock_strerror()`，清晰可控
- **C11 RAII** — `RAWSOCK_AUTO_CLOSE` 自动释放 socket，防止泄漏
- **自动解析** — `rawsock_recv_auto()` 一键接收并解析 IP/TCP/UDP/ICMP 各层信息
- **零依赖** — 仅使用标准 POSIX / Linux 系统库

## 快速开始

### 1. 复制头文件

将 `rawsock.h` 复制到你的项目中。

### 2. 在一个 .c 文件中定义实现

```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"
```

### 3. 在其他文件中正常包含

```c
#include "rawsock.h"
```

### 4. 编译运行

```bash
gcc -o myprogram myprogram.c
sudo ./myprogram    # raw socket 需要 root/CAP_NET_RAW
```

## API 分层设计

| 层级 | 函数 | 用途 |
|------|------|------|
| **L0 Core** | `rawsock_open/close/send/recv` | 核心 socket 操作 |
| **L1 Helpers** | `rawsock_bind_iface/set_timeout/pton/ntop` | 常用辅助功能 |
| **L2 Parsers** | `rawsock_parse_ip4/ip6/tcp/udp/icmp` | 协议头解析 |
| **L2 Checksum** | `rawsock_cksum/cksum_pseudo` | 校验和计算 |
| **L3 Auto** | `rawsock_recv_auto` | 一键接收并自动解析全协议栈 |

## 示例代码

### 基础示例（Core API）

```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"
#include <stdio.h>

int main(void) {
    if (!rawsock_has_caps()) {
        printf("需要 root 权限\n");
        return 1;
    }

    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    cfg.protocol = IPPROTO_ICMP;

    RAWSOCK_AUTO_CLOSE rawsock_t* sock = rawsock_open(&cfg);
    if (!sock) {
        printf("创建失败: %s\n", rawsock_strerror(rawsock_last_err(NULL)));
        return 1;
    }

    uint8_t packet[64] = {0};
    // ... 构建 ICMP echo request ...
    rawsock_send(sock, packet, sizeof(packet), "8.8.8.8");

    uint8_t buf[1024];
    int n = rawsock_recv(sock, buf, sizeof(buf));
    if (n > 0) {
        printf("收到 %d 字节\n", n);
    }

    return 0;   /* sock 自动关闭 */
}
```

### 高级示例（Auto Parse）

```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"
#include <stdio.h>

int main(void) {
    if (!rawsock_has_caps()) return 1;

    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    cfg.protocol = 0;   /* 捕获所有协议 */
    cfg.rcv_timeout_ms = 1000;

    RAWSOCK_AUTO_CLOSE rawsock_t* sock = rawsock_open(&cfg);
    if (!sock) return 1;

    uint8_t buf[RAWSOCK_MAX_PACKET];
    rawsock_pkt_t info;

    for (int i = 0; i < 10; i++) {
        int n = rawsock_recv_auto(sock, buf, sizeof(buf), &info);
        if (n > 0 && info.l4_parsed) {
            printf("%s:%u -> %s:%u  %s  %zu bytes\n",
                   info.src_ip, info.src_port,
                   info.dst_ip, info.dst_port,
                   info.protocol == IPPROTO_TCP ? "TCP" :
                   info.protocol == IPPROTO_UDP ? "UDP" : "OTHER",
                   info.pkt_len);
        }
    }
    return 0;
}
```

### 手动解析示例

```c
rawsock_ip4_t ip;
const void* payload;
size_t payload_len;
if (rawsock_parse_ip4(buf, n, &ip, &payload, &payload_len) == 0) {
    printf("协议: %d, TTL: %d\n", ip.proto, ip.ttl);
    if (ip.proto == IPPROTO_TCP && payload_len >= RAWSOCK_TCP_HLEN) {
        rawsock_tcp_t tcp;
        rawsock_parse_tcp(payload, payload_len, &tcp);
        printf("端口: %d -> %d\n", tcp.src_port, tcp.dst_port);
    }
}
```

## 错误处理

所有函数在失败时返回 `-1`（或 `NULL`），具体错误码通过 `rawsock_last_err()` 获取：

```c
RAWSOCK_AUTO_CLOSE rawsock_t* s = rawsock_open(&cfg);
if (!s) {
    rawsock_err_t err = rawsock_last_err(NULL);
    int sys_errno = rawsock_last_errno(NULL);
    printf("错误: %s (errno=%d)\n", rawsock_strerror(err), sys_errno);
}
```

## 主要数据结构

### 配置
```c
typedef struct {
    int af;              /* AF_INET / AF_INET6 */
    int protocol;        /* IPPROTO_TCP / UDP / ICMP / 0 */
    int rcv_timeout_ms;
    int snd_timeout_ms;
    bool hdr_incl;       /* IPv4 用户态构造 IP 头 */
    bool broadcast;
} rawsock_cfg_t;
```

### 解析后的数据包信息（`rawsock_pkt_t`）
```c
typedef struct {
    uint64_t timestamp_us;
    size_t   pkt_len;
    char     src_ip[46];
    char     dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ip_ver;       /* 4 or 6 */
    uint8_t  protocol;
    uint8_t  l4_parsed;    /* 1 if TCP/UDP/ICMP parsed OK */
    union {
        rawsock_tcp_t  tcp;
        rawsock_udp_t  udp;
        rawsock_icmp_t icmp;
    } l4;
} rawsock_pkt_t;
```

## C++ 封装

提供 header-only 的 C++ 封装 `rawsock.hpp`，支持 RAII 和异常：

```cpp
#include "rawsock.hpp"

int main() {
    try {
        rawsock::socket sock = rawsock::socket::open_ip4(IPPROTO_ICMP);
        uint8_t buf[1024];
        ssize_t n = sock.recv(buf, sizeof(buf));
    } catch (const rawsock::error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

编译 C++ 示例：
```bash
# C++ 示例直接定义 RAWSOCK_IMPLEMENTATION 即可
g++ -std=c++11 -o myprogram myprogram.cpp
```

## 示例程序

| 示例 | 说明 | 用法 |
|------|------|------|
| `simple_send.cpp` | 基础发送 | `sudo ./simple_send [udp\|icmp]` |
| `simple_capture.cpp` | 基础抓包 | `sudo ./simple_capture [proto] [iface]` |
| `arp_scan.cpp` | ARP 扫描器 | `sudo ./arp_scan 192.168.1.0/24` |
| `ping_sweep.cpp` | ICMP 探测 | `sudo ./ping_sweep 192.168.1.0/24` |
| `arp_monitor.cpp` | ARP 欺骗检测 | `sudo ./arp_monitor [iface]` |
| `packet_logger.cpp` | 数据包记录 | `sudo ./packet_logger output.log [tcp\|udp\|icmp\|all]` |

> **Loopback 注意**：捕获 127.0.0.1 的包需要绑定到 loopback 接口：
> ```bash
> sudo ./simple_capture udp lo   # Linux
> sudo ./simple_capture udp lo0  # macOS
> ```

编译所有示例：
```bash
g++ -std=c++11 -o examples/arp_scan      examples/arp_scan.cpp
g++ -std=c++11 -o examples/ping_sweep   examples/ping_sweep.cpp
g++ -std=c++11 -o examples/arp_monitor  examples/arp_monitor.cpp
g++ -std=c++11 -o examples/packet_logger examples/packet_logger.cpp
g++ -std=c++11 -o examples/simple_capture examples/simple_capture.cpp
g++ -std=c++11 -o examples/simple_send   examples/simple_send.cpp
```

## 编译测试

```bash
# C 单元测试（离线）
gcc -o tests/offline_unit_test tests/offline_unit_test.c
./tests/offline_unit_test

# C send/recv 测试（需要 root）
sudo ./tests/send_recv_test

# 运行抓包示例
sudo ./examples/capture tcp
```

## 注意事项

1. **权限**：raw socket 需要 root 或 `CAP_NET_RAW` capability
2. **单实现规则**：`RAWSOCK_IMPLEMENTATION` 只能在一个 .c 文件中定义，否则会出现重复定义链接错误
3. **缓冲区**：建议使用 `RAWSOCK_MAX_PACKET` (65535) 字节的缓冲区
4. **平台**：主要支持 Linux；macOS 部分功能受限（如 `SO_BINDTODEVICE` 不可用）

## 许可证

MIT License
