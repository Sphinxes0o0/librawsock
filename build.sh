#!/bin/bash

# LibRawSock 构建脚本
# 使用 CMake 构建系统

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认配置
BUILD_TYPE="Release"
BUILD_DIR="build"
INSTALL_PREFIX=""
BUILD_TESTS=OFF
BUILD_EXAMPLES=OFF
BUILD_TOOLS=OFF
ENABLE_COVERAGE=OFF
CLEAN_BUILD=0
VERBOSE=0
JOBS=$(nproc)

# 日志函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 帮助信息
show_help() {
    cat << EOF
LibRawSock 构建脚本

用法: $0 [选项]

选项:
  -t, --type TYPE         构建类型 (Debug|Release|RelWithDebInfo|MinSizeRel) [默认: Release]
  -d, --build-dir DIR     构建目录 [默认: build]
  -p, --prefix PREFIX     安装前缀
  -j, --jobs NUM          并行编译任务数 [默认: $(nproc)]
  
  构建组件:
  --tests                 构建单元测试
  --examples              构建示例程序
  --tools                 构建开发工具
  --all                   构建所有组件 (等价于 --tests --examples --tools)
  
  其他选项:
  --coverage              启用代码覆盖率
  --clean                 清理构建目录
  --verbose               详细输出
  -h, --help              显示此帮助信息

示例:
  $0                      # 仅构建核心库
  $0 --all                # 构建所有组件
  $0 --tests --tools      # 构建库、测试和工具
  $0 --type Debug --coverage --tests  # Debug构建并启用覆盖率
  $0 --clean --all        # 清理后重新构建所有组件

EOF
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -d|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -p|--prefix)
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        --tests)
            BUILD_TESTS=ON
            shift
            ;;
        --examples)
            BUILD_EXAMPLES=ON
            shift
            ;;
        --tools)
            BUILD_TOOLS=ON
            shift
            ;;
        --all)
            BUILD_TESTS=ON
            BUILD_EXAMPLES=ON
            BUILD_TOOLS=ON
            shift
            ;;
        --coverage)
            ENABLE_COVERAGE=ON
            shift
            ;;
        --clean)
            CLEAN_BUILD=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
done

# 检查环境
log_info "检查构建环境..."

# 检查 CMake
if ! command -v cmake &> /dev/null; then
    log_error "CMake 未找到，请先安装 CMake"
    exit 1
fi

CMAKE_VERSION=$(cmake --version | head -n1 | cut -d' ' -f3)
log_info "找到 CMake 版本: $CMAKE_VERSION"

# 检查编译器
if ! command -v gcc &> /dev/null; then
    log_error "GCC 未找到，请先安装 GCC"
    exit 1
fi

GCC_VERSION=$(gcc --version | head -n1)
log_info "找到编译器: $GCC_VERSION"

# 清理构建目录
if [[ $CLEAN_BUILD -eq 1 ]]; then
    log_info "清理构建目录: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

# 创建构建目录
log_info "创建构建目录: $BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 配置CMake选项
CMAKE_OPTIONS=(
    "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
    "-DBUILD_TESTS=$BUILD_TESTS"
    "-DBUILD_EXAMPLES=$BUILD_EXAMPLES"
    "-DBUILD_TOOLS=$BUILD_TOOLS"
    "-DENABLE_COVERAGE=$ENABLE_COVERAGE"
)

if [[ -n "$INSTALL_PREFIX" ]]; then
    CMAKE_OPTIONS+=("-DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX")
fi

if [[ $VERBOSE -eq 1 ]]; then
    CMAKE_OPTIONS+=("-DCMAKE_VERBOSE_MAKEFILE=ON")
fi

# 显示配置信息
log_info "构建配置:"
echo "  构建类型: $BUILD_TYPE"
echo "  构建目录: $BUILD_DIR"
echo "  并行任务: $JOBS"
echo "  单元测试: $BUILD_TESTS"
echo "  示例程序: $BUILD_EXAMPLES"
echo "  开发工具: $BUILD_TOOLS"
echo "  代码覆盖: $ENABLE_COVERAGE"
if [[ -n "$INSTALL_PREFIX" ]]; then
    echo "  安装前缀: $INSTALL_PREFIX"
fi

# 运行 CMake 配置
log_info "配置项目..."
cd "$BUILD_DIR"

if [[ $VERBOSE -eq 1 ]]; then
    cmake "${CMAKE_OPTIONS[@]}" ..
else
    cmake "${CMAKE_OPTIONS[@]}" .. > /dev/null
fi

if [[ $? -eq 0 ]]; then
    log_success "配置完成"
else
    log_error "配置失败"
    exit 1
fi

# 编译项目
log_info "编译项目 (使用 $JOBS 个并行任务)..."

if [[ $VERBOSE -eq 1 ]]; then
    make -j$JOBS
else
    make -j$JOBS > /dev/null
fi

if [[ $? -eq 0 ]]; then
    log_success "编译完成"
else
    log_error "编译失败"
    exit 1
fi

# 显示构建结果
log_info "构建结果:"
echo "  库文件: $(find lib -name "*.so" -o -name "*.a" 2>/dev/null | wc -l) 个"
echo "  可执行文件: $(find bin -type f -executable 2>/dev/null | wc -l) 个"

if [[ $BUILD_TESTS == "ON" ]]; then
    echo "  测试程序: $(find bin -name "test_*" 2>/dev/null | wc -l) 个"
fi

# 运行快速验证
log_info "运行快速验证..."

if [[ -f "lib/librawsock.so" ]] || [[ -f "lib/librawsock.a" ]]; then
    log_success "核心库构建成功"
else
    log_error "核心库构建失败"
    exit 1
fi

# 运行测试 (如果构建了)
if [[ $BUILD_TESTS == "ON" ]]; then
    log_info "运行单元测试..."
    if ctest --output-on-failure -j$JOBS; then
        log_success "所有测试通过"
    else
        log_warning "部分测试失败 (可能需要特殊权限)"
    fi
fi

# 构建完成
cd ..
log_success "构建完成!"

# 使用说明
echo ""
log_info "使用说明:"
echo "  库文件位置: $BUILD_DIR/lib/"
echo "  头文件位置: include/"

if [[ $BUILD_EXAMPLES == "ON" ]]; then
    echo "  示例程序: $BUILD_DIR/bin/"
    echo "    运行演示: cd $BUILD_DIR && ./bin/demo_tcp_analysis -d"
fi

if [[ $BUILD_TOOLS == "ON" ]]; then
    echo "  开发工具: $BUILD_DIR/bin/"
    echo "    性能测试: cd $BUILD_DIR && ./bin/benchmark --all"
    echo "    网络诊断: cd $BUILD_DIR && sudo ./bin/netdiag"
fi

if [[ $BUILD_TESTS == "ON" ]]; then
    echo "  测试程序: $BUILD_DIR/bin/"
    echo "    运行测试: cd $BUILD_DIR && ctest"
fi

echo ""
echo "安装命令: cd $BUILD_DIR && sudo make install"
