# LibRawSock CMake 构建指南

## 概述

LibRawSock 使用现代化的 CMake 构建系统，支持模块化编译和灵活的组件选择。本指南详细介绍如何使用CMake构建和配置项目。

## 快速开始

### 使用构建脚本 (推荐)

```bash
# 基本构建 (仅核心库)
./build.sh

# 构建所有组件
./build.sh --all

# Debug 构建并启用测试
./build.sh --type Debug --tests --coverage

# 查看完整选项
./build.sh --help
```

### 手动 CMake 构建

```bash
# 创建构建目录
mkdir build && cd build

# 配置项目
cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTS=ON \
      -DBUILD_EXAMPLES=ON \
      ..

# 编译
make -j$(nproc)

# 运行测试
ctest

# 安装
sudo make install
```

## 构建选项详解

### 核心选项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CMAKE_BUILD_TYPE` | String | Release | 构建类型：Debug, Release, RelWithDebInfo, MinSizeRel |
| `BUILD_SHARED_LIBS` | Bool | ON | 构建动态库 |
| `BUILD_STATIC_LIBS` | Bool | ON | 构建静态库 |
| `CMAKE_INSTALL_PREFIX` | Path | /usr/local | 安装路径前缀 |

### 组件选项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `BUILD_TESTS` | Bool | OFF | 构建单元测试 |
| `BUILD_EXAMPLES` | Bool | OFF | 构建示例程序 |
| `BUILD_TOOLS` | Bool | OFF | 构建开发工具 |

### 高级选项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `ENABLE_COVERAGE` | Bool | OFF | 启用代码覆盖率 |
| `CMAKE_VERBOSE_MAKEFILE` | Bool | OFF | 详细构建输出 |

## 构建目标

### 核心库目标

```bash
# 仅构建核心库
make rawsock_shared rawsock_static

# 构建对象库
make rawsock_objects
```

### 测试目标

```bash
# 构建所有测试
make test_rawsock test_packet test_analyzer

# 运行特定测试
./bin/test_rawsock
./bin/test_packet
./bin/test_analyzer

# 运行所有测试
ctest

# 运行特定标签的测试
ctest -L unit
ctest -L integration
```

### 示例目标

```bash
# 构建所有示例
make ping tcp_syn_scan packet_sniffer
make simple_tcp_monitor tcp_connection_analyzer
make demo_tcp_analysis

# 运行演示
./bin/demo_tcp_analysis -d -v
```

### 工具目标

```bash
# 构建开发工具
make perf_analyzer benchmark netdiag

# 运行工具
./bin/benchmark --all
sudo ./bin/netdiag
./bin/perf_analyzer -c 1000
```

## 自定义目标

### 测试相关

```bash
# 运行单元测试
make test_unit

# 运行内存检查测试 (需要Valgrind)
make test_memory

# 运行所有测试
make test_all

# 生成覆盖率报告 (需要启用ENABLE_COVERAGE)
make coverage

# 清理覆盖率数据
make coverage_clean
```

### 示例相关

```bash
# 显示可用演示
make demo

# 运行快速演示
make demo_quick

# 验证示例程序
make verify_examples
```

### 工具相关

```bash
# 测试开发工具
make test_tools

# 运行性能基准
make run_benchmarks

# 运行网络诊断
make run_netdiag
```

## 安装和打包

### 安装

```bash
# 安装所有组件
sudo make install

# 安装特定组件
sudo make install/fast
sudo cmake --install . --component shared
sudo cmake --install . --component static
sudo cmake --install . --component tests
```

### 创建包

```bash
# 生成源码包
make package_source

# 生成二进制包 (DEB/TGZ)
make package

# 创建特定格式的包
cpack -G DEB
cpack -G TGZ
```

## 跨平台构建

### Linux

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake
cmake -B build .

# CentOS/RHEL
sudo yum install gcc gcc-c++ cmake
cmake -B build .
```

### macOS

```bash
# 使用 Homebrew
brew install cmake
cmake -B build .
```

### Windows (使用 MinGW)

```bash
# 使用 MSYS2
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc
cmake -B build -G "MinGW Makefiles" .
```

## 集成到其他项目

### find_package 方式

```cmake
find_package(librawsock REQUIRED)
target_link_libraries(your_target PRIVATE librawsock::rawsock)
```

### pkg-config 方式

```bash
# 编译时
gcc $(pkg-config --cflags librawsock) your_code.c \
    $(pkg-config --libs librawsock) -o your_program
```

### 子模块方式

```cmake
add_subdirectory(librawsock)
target_link_libraries(your_target PRIVATE rawsock)
```

## 故障排除

### 常见问题

1. **权限错误**
   ```bash
   # 解决方案：使用root权限或设置capabilities
   sudo ./bin/ping 8.8.8.8
   sudo setcap cap_net_raw=eip ./bin/ping
   ```

2. **库找不到**
   ```bash
   # 解决方案：设置库路径
   export LD_LIBRARY_PATH=$PWD/build/lib:$LD_LIBRARY_PATH
   ```

3. **头文件找不到**
   ```bash
   # 解决方案：检查安装
   cmake --install build --config Release
   ```

### 调试构建

```bash
# 详细输出
make VERBOSE=1

# Debug 构建
cmake -DCMAKE_BUILD_TYPE=Debug ..

# 启用所有警告
cmake -DCMAKE_C_FLAGS="-Wall -Wextra -Werror" ..
```

## 性能优化

### 发布构建

```bash
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-O3 -DNDEBUG" \
      ..
```

### 链接时优化

```bash
cmake -DCMAKE_C_FLAGS="-flto" \
      -DCMAKE_EXE_LINKER_FLAGS="-flto" \
      ..
```

## 开发工作流

### 日常开发

```bash
# 1. 编辑代码
vim src/rawsock.c

# 2. 增量构建
cd build && make

# 3. 运行测试
ctest --output-on-failure

# 4. 运行演示
./bin/demo_tcp_analysis -d
```

### 提交前检查

```bash
# 完整重新构建
./build.sh --clean --all

# 运行所有测试
cd build && ctest

# 检查覆盖率
./build.sh --type Debug --tests --coverage
cd build && make coverage
```

这个现代化的CMake构建系统为LibRawSock提供了灵活、可扩展的编译环境，支持从简单的库使用到复杂的开发工作流程。
