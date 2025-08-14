# LibRawSock CMake Build Guide

## Overview

LibRawSock uses a modern CMake build system that supports modular compilation and flexible component selection. This guide details how to use CMake to build and configure the project.

## Quick Start

### Using Build Script (Recommended)

```bash
# Basic build (core library only)
./build.sh

# Build all components
./build.sh --all

# Debug build with tests enabled
./build.sh --type Debug --tests --coverage

# View all options
./build.sh --help
```

### Manual CMake Build

```bash
# Create build directory
mkdir build && cd build

# Configure project
cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTS=ON \
      -DBUILD_EXAMPLES=ON \
      ..

# Compile
make -j$(nproc)

# Run tests
ctest

# Install
sudo make install
```

## Build Option Details

### Core Options

| Option | Type | Default | Description |
|------|------|--------|------|
| `CMAKE_BUILD_TYPE` | String | Release | Build type: Debug, Release, RelWithDebInfo, MinSizeRel |
| `BUILD_SHARED_LIBS` | Bool | ON | Build dynamic library |
| `BUILD_STATIC_LIBS` | Bool | ON | Build static library |
| `CMAKE_INSTALL_PREFIX` | Path | /usr/local | Installation prefix |

### Component Options

| Option | Type | Default | Description |
|------|------|--------|------|
| `BUILD_TESTS` | Bool | OFF | Build unit tests |
| `BUILD_EXAMPLES` | Bool | OFF | Build example programs |
| `BUILD_TOOLS` | Bool | OFF | Build development tools |

### Advanced Options

| Option | Type | Default | Description |
|------|------|--------|------|
| `ENABLE_COVERAGE` | Bool | OFF | Enable code coverage |
| `CMAKE_VERBOSE_MAKEFILE` | Bool | OFF | Detailed build output |

## Build Targets

### Core Library Targets

```bash
# Build only core library
make rawsock_shared rawsock_static

# Build object library
make rawsock_objects
```

### Test Targets

```bash
# Build all tests
make test_rawsock test_packet test_analyzer

# Run specific tests
./bin/test_rawsock
./bin/test_packet
./bin/test_analyzer

# Run all tests
ctest

# Run tests with specific tags
ctest -L unit
ctest -L integration
```

### Example Targets

```bash
# Build all examples
make ping tcp_syn_scan packet_sniffer
make simple_tcp_monitor tcp_connection_analyzer
make demo_tcp_analysis

# Run demo
./bin/demo_tcp_analysis -d -v
```

### Tool Targets

```bash
# Build development tools
make perf_analyzer benchmark netdiag

# Run tools
./bin/benchmark --all
sudo ./bin/netdiag
./bin/perf_analyzer -c 1000
```

## Custom Targets

### Test Related

```bash
# Run unit tests
make test_unit

# Run memory check tests (requires Valgrind)
make test_memory

# Run all tests
make test_all

# Generate coverage report (requires ENABLE_COVERAGE)
make coverage

# Clean coverage data
make coverage_clean
```

### Example Related

```bash
# Show available demos
make demo

# Run quick demo
make demo_quick

# Verify example programs
make verify_examples
```

### Tool Related

```bash
# Test development tools
make test_tools

# Run performance benchmarks
make run_benchmarks

# Run network diagnostics
make run_netdiag
```

## Installation and Packaging

### Installation

```bash
# Install all components
sudo make install

# Install specific components
sudo make install/fast
sudo cmake --install . --component shared
sudo cmake --install . --component static
sudo cmake --install . --component tests
```

### Creating Packages

```bash
# Generate source package
make package_source

# Generate binary package (DEB/TGZ)
make package

# Create specific format packages
cpack -G DEB
cpack -G TGZ
```

## Cross-Platform Build

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
# Using Homebrew
brew install cmake
cmake -B build .
```

### Windows (using MinGW)

```bash
# Using MSYS2
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc
cmake -B build -G "MinGW Makefiles" .
```

## Integrating with Other Projects

### find_package Method

```cmake
find_package(librawsock REQUIRED)
target_link_libraries(your_target PRIVATE librawsock::rawsock)
```

### pkg-config Method

```bash
# During compilation
gcc $(pkg-config --cflags librawsock) your_code.c \
    $(pkg-config --libs librawsock) -o your_program
```

### Submodule Method

```cmake
add_subdirectory(librawsock)
target_link_libraries(your_target PRIVATE rawsock)
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Solution: Use root privileges or set capabilities
   sudo ./bin/ping 8.8.8.8
   sudo setcap cap_net_raw=eip ./bin/ping
   ```

2. **Library Not Found**
   ```bash
   # Solution: Set library path
   export LD_LIBRARY_PATH=$PWD/build/lib:$LD_LIBRARY_PATH
   ```

3. **Header Files Not Found**
   ```bash
   # Solution: Check installation
   cmake --install build --config Release
   ```

### Debugging Build

```bash
# Detailed output
make VERBOSE=1

# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Enable all warnings
cmake -DCMAKE_C_FLAGS="-Wall -Wextra -Werror" ..
```

## Performance Optimization

### Release Build

```bash
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-O3 -DNDEBUG" \
      ..
```

### Link-Time Optimization

```bash
cmake -DCMAKE_C_FLAGS="-flto" \
      -DCMAKE_EXE_LINKER_FLAGS="-flto" \
      ..
```

## Development Workflow

### Daily Development

```bash
# 1. Edit code
vim src/rawsock.c

# 2. Incremental build
cd build && make

# 3. Run tests
ctest --output-on-failure

# 4. Run demo
./bin/demo_tcp_analysis -d
```

### Pre-Commit Check

```bash
# Full rebuild
./build.sh --clean --all

# Run all tests
cd build && ctest

# Check coverage
./build.sh --type Debug --tests --coverage
cd build && make coverage
```

This modern CMake build system provides a flexible, extensible compilation environment for LibRawSock, supporting everything from simple library usage to complex development workflows.
