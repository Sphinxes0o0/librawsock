# LibRawSock 使用用例

本页给出基于现有示例与API的“可直接运行”的使用用例，涵盖网络监控、性能分析、故障排查与安全分析等典型场景。

- 先决条件
  - Linux 系统，已安装构建工具（gcc/clang、cmake、make）
  - 原始套接字需要 root 或 CAP_NET_RAW 权限（部分用例可使用演示模式免 root）
  - 项目根目录执行构建脚本

```bash
# 构建所有组件（库 + 测试 + 示例 + 工具）
./build.sh --all
# 或仅构建示例
./build.sh --examples
```

构建完成后，示例二进制位于 `build/bin/`。

## 用例 1：ICMP Ping（网络连通性验证）

- 目标：验证到目标主机的连通性与往返时延（RTT）
- 程序：`examples/ping.c`
- 运行：
```bash
sudo ./build/bin/ping 8.8.8.8 -c 3
```
- 要点：
  - 使用 `rawsock_packet_builder_*` 构造 IPv4 + ICMP 报文
  - 使用 `rawsock_send`/`rawsock_recv` 发送接收

## 用例 2：TCP SYN 扫描（端口可达性）

- 目标：快速判断目标主机端口开放情况
- 程序：`examples/tcp_syn_scan.c`
- 运行：
```bash
sudo ./build/bin/tcp_syn_scan 192.168.1.10 1 1024
```
- 要点：
  - 发送 SYN，依据对端返回 SYN-ACK/RST 判断端口状态

## 用例 3：数据包嗅探（基础抓包）

- 目标：在指定网卡实时抓取并打印基础包信息
- 程序：`examples/packet_sniffer.c`
- 运行：
```bash
sudo ./build/bin/packet_sniffer eth0
```
- 要点：
  - 使用原始套接字接收，解析 IPv4/TCP/UDP/ICMP 头部

## 用例 4：TCP 连接分析（性能与状态）

- 目标：跟踪 TCP 连接状态、统计与性能（RTT、重传等）
- 程序：`examples/tcp_connection_analyzer.c`
- 运行：
```bash
sudo ./build/bin/tcp_connection_analyzer -v -s
```
- 要点：
  - `analyzer_create` + `tcp_analyzer_create` 注册处理器
  - 设置 `connection_callback` / `data_callback`
  - 输出连接状态、字节计数、平均 RTT 等

## 用例 5：简单 TCP 监控（轻量追踪）

- 目标：以极简方式追踪一定数量的 TCP 连接
- 程序：`examples/simple_tcp_monitor.c`
- 运行：
```bash
sudo ./build/bin/simple_tcp_monitor 50
```

## 用例 6：TCP 分析演示（免 root 模拟）

- 目标：无权限环境下快速体验 TCP 三次握手、HTTP 往返与连接关闭的分析流程
- 程序：`examples/demo_tcp_analysis.c`
- 运行（模拟）：
```bash
./build/bin/demo_tcp_analysis -d -v
```
- 要点：
  - 通过 `rawsock_packet_builder_*` 构造并注入模拟包，驱动 `analyzer_process_packet`

## 用例 7：库 API 内嵌最小示例

- 原始套接字最小用法：
```c
#include <librawsock/rawsock.h>

void example_send_icmp() {
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) return;
    uint8_t pkt[64] = {0};
    /* 构造 pkt ... */
    (void)rawsock_send(sock, pkt, sizeof(pkt), "8.8.8.8");
    rawsock_destroy(sock);
}
```

- 协议分析最小用法：
```c
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

void example_analyze(const uint8_t* data, size_t len) {
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* h = tcp_analyzer_create();
    analyzer_register_handler(ctx, h);
    struct timeval ts; gettimeofday(&ts, NULL);
    (void)analyzer_process_packet(ctx, data, len, &ts);
    tcp_analyzer_destroy(h);
    analyzer_destroy(ctx);
}
```

## 用例 8：测试与覆盖率

```bash
# 构建并运行全部单元测试
./build.sh --tests
cd build && ctest --output-on-failure

# 单独运行分类
./build/bin/test_analyzer
./build/bin/test_packet
./build/bin/test_rawsock

# Valgrind（如已安装）
ctest -L valgrind --output-on-failure

# 覆盖率（配置时启用 -DENABLE_COVERAGE=ON）
make coverage
```

## 用例 9：权限与故障排查

- 原始套接字权限：
```bash
# 以 root 运行，或授予二进制 CAP_NET_RAW
sudo setcap cap_net_raw=eip ./build/bin/packet_sniffer
```
- 常见问题
  - 非 root 收到 “Insufficient permissions”：使用 `sudo` 或 `setcap`
  - IPv6 不可用：确认内核与系统启用 IPv6
  - 接收超时：调整 `rawsock_create_with_config` 的 `recv_timeout_ms`

## 关联文档

- API 参考：`docs/api.md`
- TCP 分析器指南：`docs/tcp_usage_guide.md`
- 示例源码：`examples/`