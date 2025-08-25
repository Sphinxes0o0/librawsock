# Changelog

## [1.0.0] - 2024-12-25

### 🎉 Major Release - Single Header Library

#### Changed
- **完全重构为单头文件库** - 整个库现在只需要一个 `rawsock.h` 文件
- **改进的跨平台兼容性** - 支持 Linux 和 macOS
- **更好的C标准支持** - 支持 C99, C11, GNU11 标准编译
- **简化的集成方式** - 只需复制一个文件到项目中

#### Features
- ✅ IPv4/IPv6 原始套接字支持
- ✅ 数据包发送和接收
- ✅ 协议头部解析 (IP, TCP, UDP, ICMP)
- ✅ 校验和计算工具
- ✅ IP地址转换工具
- ✅ 错误处理机制
- ✅ 超时控制
- ✅ 接口绑定（Linux）

#### Compatibility
- **编译器**: GCC, Clang
- **C标准**: C99, C11, GNU11
- **平台**: Linux, macOS
- **架构**: x86_64, ARM64

#### CI/CD
- 新的GitHub Actions工作流
- 多编译器测试 (GCC, Clang)
- 多标准测试 (C99, C11, GNU11)
- 跨平台测试 (Linux, macOS)
- 静态代码分析 (cppcheck, clang-tidy)

#### Usage
```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"

int main(void) {
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    // ... 使用套接字 ...
    rawsock_destroy(sock);
    return 0;
}
```

#### Migration from Old Version
如果你使用的是旧版本的多文件库：
1. 删除所有旧的源文件和头文件
2. 复制新的 `rawsock.h` 到项目
3. 在一个源文件中定义 `RAWSOCK_IMPLEMENTATION`
4. 重新编译项目

#### Known Limitations
- macOS 上某些原始套接字功能受限
- 需要 root 权限或 CAP_NET_RAW 能力
- SO_BINDTODEVICE 仅在 Linux 上可用

#### Files
- `rawsock.h` - 单头文件库
- `example.c` - 使用示例
- `test_single_header.c` - 完整测试套件
- `simple_test.c` - 简单测试程序
- `README.md` - 中文文档
- `README_SINGLE_HEADER.md` - 英文文档

---

### Previous Versions
This is the first release of the single-header version.