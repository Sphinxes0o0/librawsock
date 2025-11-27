# rawsock - AF_PACKET 网络抓包库

[![CI](https://github.com/Sphinxes0o0/librawsock/actions/workflows/ci.yml/badge.svg)](https://github.com/Sphinxes0o0/librawsock/actions/workflows/ci.yml)

一个轻量级的 AF_PACKET 网络抓包库，采用 Boost 风格编码规范，无外部依赖，同时提供 C/C++ 接口。

## 特性

- **无外部依赖** - 仅使用标准系统库
- **AF_PACKET 支持** - 使用 Linux AF_PACKET 接口进行高性能网络抓包
- **双接口支持** - 同时提供现代 C++11 和纯 C 接口
- **Boost 风格** - 采用 Boost 编码规范，代码清晰易读
- **头文件库** - C++ 接口为纯头文件库，无需编译
- **完整文档** - 详细的 API 文档和示例代码
- **单元测试** - 完善的单元测试覆盖

## 快速开始

### 安装

```bash
git clone https://github.com/Sphinxes0o0/librawsock.git
cd librawsock
mkdir build && cd build
cmake ..
make
sudo make install
```

### C++ 使用示例

```cpp
#include <rawsock/rawsock.hpp>
#include <iostream>
#include <vector>

int main() {
    // 检查权限
    if (!rawsock::capture::check_privileges()) {
        std::cerr << "需要 root 权限\n";
        return 1;
    }
    
    // 配置抓包
    rawsock::capture_config config;
    config.interface_name = "eth0";
    config.filter_protocol = rawsock::protocol::tcp;
    config.promiscuous = true;
    
    // 创建并打开抓包器
    rawsock::capture cap;
    if (cap.open(config) != rawsock::error_code::success) {
        std::cerr << "打开抓包器失败\n";
        return 1;
    }
    
    // 抓取数据包
    std::vector<uint8_t> buffer(rawsock::constants::max_packet_size);
    rawsock::packet_info info;
    
    int bytes = cap.capture_next(buffer.data(), buffer.size(), &info);
    if (bytes > 0) {
        std::cout << "抓到包: " << info.src_addr << ":" << info.src_port 
                  << " -> " << info.dst_addr << ":" << info.dst_port << "\n";
    }
    
    return 0;
}
```

### C 使用示例

```c
#include <rawsock/rawsock_c.h>
#include <stdio.h>

int main() {
    // 检查权限
    if (!rawsock_check_privileges()) {
        printf("需要 root 权限\n");
        return 1;
    }
    
    // 创建抓包器
    rawsock_capture_t* cap = rawsock_capture_create();
    if (!cap) return 1;
    
    // 配置
    rawsock_config_t config;
    rawsock_config_init(&config);
    strcpy(config.interface_name, "eth0");
    config.filter_protocol = RAWSOCK_PROTO_TCP;
    config.promiscuous = 1;
    
    // 打开
    if (rawsock_capture_open(cap, &config) != RAWSOCK_SUCCESS) {
        printf("打开抓包器失败\n");
        rawsock_capture_destroy(cap);
        return 1;
    }
    
    // 抓包
    uint8_t buffer[RAWSOCK_MAX_PACKET_SIZE];
    rawsock_packet_info_t info;
    
    int bytes = rawsock_capture_next(cap, buffer, sizeof(buffer), &info);
    if (bytes > 0) {
        printf("抓到包: %s:%u -> %s:%u\n",
               info.src_addr, info.src_port,
               info.dst_addr, info.dst_port);
    }
    
    rawsock_capture_destroy(cap);
    return 0;
}
```

### 编译

```bash
# C++ 程序
g++ -std=c++11 -o myapp myapp.cpp -I/usr/local/include -L/usr/local/lib -lrawsock

# C 程序
gcc -o myapp myapp.c -I/usr/local/include -L/usr/local/lib -lrawsock

# 运行（需要 root 权限）
sudo ./myapp
```

## API 文档

### C++ 接口

#### 主要类

| 类 | 描述 |
|---|---|
| `rawsock::capture` | 网络抓包主类 |
| `rawsock::capture_config` | 抓包配置 |
| `rawsock::packet_info` | 数据包信息 |

#### 协议常量

```cpp
namespace rawsock {
enum class protocol : uint8_t {
    all = 0,       // 所有协议
    icmp = 1,      // ICMP
    tcp = 6,       // TCP
    udp = 17,      // UDP
    icmpv6 = 58,   // ICMPv6
    raw = 255      // 原始 IP
};
}
```

#### 错误码

```cpp
namespace rawsock {
enum class error_code {
    success = 0,
    invalid_argument,
    socket_create_failed,
    socket_bind_failed,
    send_failed,
    recv_failed,
    permission_denied,
    timeout,
    buffer_too_small,
    interface_not_found,
    not_supported,
    unknown_error
};
}
```

### C 接口

#### 主要函数

| 函数 | 描述 |
|---|---|
| `rawsock_capture_create()` | 创建抓包器 |
| `rawsock_capture_destroy()` | 销毁抓包器 |
| `rawsock_capture_open()` | 打开抓包 |
| `rawsock_capture_close()` | 关闭抓包 |
| `rawsock_capture_next()` | 抓取下一个包 |
| `rawsock_capture_send()` | 发送原始包 |

## 项目结构

```
librawsock/
├── include/rawsock/     # 头文件
│   ├── config.hpp       # 配置和平台检测
│   ├── error.hpp        # 错误处理
│   ├── packet.hpp       # 数据包结构
│   ├── capture.hpp      # 抓包功能
│   ├── rawsock.hpp      # C++ 主头文件
│   └── rawsock_c.h      # C 接口头文件
├── src/                 # 源文件
│   └── rawsock_c.cpp    # C 接口实现
├── tests/               # 单元测试
├── examples/            # 示例代码
├── cmake/               # CMake 配置
└── CMakeLists.txt       # CMake 主文件
```

## 构建和测试

### 构建

```bash
mkdir build && cd build
cmake ..
make
```

### 运行测试

```bash
cd build
ctest --output-on-failure
```

### 安装

```bash
sudo make install
```

## 平台支持

- **Linux** - 完整支持（AF_PACKET）
- **macOS** - 不支持（AF_PACKET 仅 Linux 可用）
- **Windows** - 不支持

## 注意事项

1. **权限要求** - 抓包操作需要 root 权限或 CAP_NET_RAW capability
2. **网卡选择** - 使用 `interface_name` 指定网卡，留空表示所有网卡
3. **协议过滤** - 使用 `filter_protocol` 过滤特定协议
4. **混杂模式** - 设置 `promiscuous = true` 启用混杂模式

## 许可证

MIT License

Copyright (c) 2024 Sphinxes0o0

## 贡献

欢迎提交 Issue 和 Pull Request！