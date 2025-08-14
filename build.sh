#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    cat << EOF
LibRawSock Build Script

Usage: $0 [options]

Options:
  -t, --type TYPE         Build type (Debug|Release|RelWithDebInfo|MinSizeRel) [default: Release]
  -d, --build-dir DIR     Build directory [default: build]
  -p, --prefix PREFIX     Installation prefix
  -j, --jobs NUM          Number of parallel compilation jobs [default: $(nproc)]

  Build components:
  --tests                 Build unit tests
  --examples              Build example programs
  --tools                 Build development tools
  --all                   Build all components (equivalent to --tests --examples --tools)

  Other options:
  --coverage              Enable code coverage
  --clean                 Clean build directory
  --verbose               Verbose output
  -h, --help              Show this help information

Examples:
  $0                      # Build core library only
  $0 --all                # Build all components
  $0 --tests --tools      # Build library, tests and tools
  $0 --type Debug --coverage --tests  # Debug build with coverage
  $0 --clean --all        # Clean and rebuild all components

EOF
}

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
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

log_info "Checking build environment..."

if ! command -v cmake &> /dev/null; then
    log_error "CMake not found, please install CMake first"
    exit 1
fi

CMAKE_VERSION=$(cmake --version | head -n1 | cut -d' ' -f3)
log_info "Found CMake version: $CMAKE_VERSION"

if ! command -v gcc &> /dev/null; then
    log_error "GCC not found, please install GCC first"
    exit 1
fi

GCC_VERSION=$(gcc --version | head -n1)
log_info "Found compiler: $GCC_VERSION"

if [[ $CLEAN_BUILD -eq 1 ]]; then
    log_info "Cleaning build directory: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi


log_info "Creating build directory: $BUILD_DIR"
mkdir -p "$BUILD_DIR"

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

log_info "Building configuration:"
echo "   Build type: $BUILD_TYPE"
echo "   Build directory: $BUILD_DIR"
echo "   Parallel jobs: $JOBS"
echo "   Unit tests: $BUILD_TESTS"
echo "   Example programs: $BUILD_EXAMPLES"
echo "   Development tools: $BUILD_TOOLS"
echo "   Code coverage: $ENABLE_COVERAGE"
if [[ -n "$INSTALL_PREFIX" ]]; then
    echo "   Installation prefix: $INSTALL_PREFIX"
fi

log_info "Configuring project..."
cd "$BUILD_DIR"

if [[ $VERBOSE -eq 1 ]]; then
    cmake "${CMAKE_OPTIONS[@]}" ..
else
    cmake "${CMAKE_OPTIONS[@]}" .. > /dev/null
fi

if [[ $? -eq 0 ]]; then
    log_success "Configuration completed"
else
    log_error "Configuration failed"
    exit 1
fi

log_info "Compiling project (using $JOBS parallel jobs)..."

if [[ $VERBOSE -eq 1 ]]; then
    make -j$JOBS
else
    make -j$JOBS > /dev/null
fi

if [[ $? -eq 0 ]]; then
    log_success "Compilation completed"
else
    log_error "Compilation failed"
    exit 1
fi

log_info "Build results:"
echo "   Library files: $(find lib -name "*.so" -o -name "*.a" 2>/dev/null | wc -l) files"
echo "   Executable files: $(find bin -type f -executable 2>/dev/null | wc -l) files"

if [[ $BUILD_TESTS == "ON" ]]; then
    echo "   Test programs: $(find bin -name "test_*" 2>/dev/null | wc -l) files"
fi


log_info "Running quick validation..."

if [[ -f "lib/librawsock.so" ]] || [[ -f "lib/librawsock.a" ]]; then
    log_success "Core library built successfully"
else
    log_error "Core library built failed"
    exit 1
fi

if [[ $BUILD_TESTS == "ON" ]]; then
    log_info "Running unit tests..."
    if ctest --output-on-failure -j$JOBS; then
        log_success "All tests passed"
    else
        log_warning "Some tests failed (may require special privileges)"
    fi
fi

cd ..
log_success "Build completed!"

echo ""
log_info "Usage:"
echo "   Library files: $BUILD_DIR/lib/"
echo "   Header files: include/"

if [[ $BUILD_EXAMPLES == "ON" ]]; then
    echo "   Example programs: $BUILD_DIR/bin/"
    echo "     Run demo: cd $BUILD_DIR && ./bin/demo_tcp_analysis -d"
fi

if [[ $BUILD_TOOLS == "ON" ]]; then
    echo "   Development tools: $BUILD_DIR/bin/"
    echo "     Performance test: cd $BUILD_DIR && ./bin/benchmark --all"
    echo "     Network diagnosis: cd $BUILD_DIR && sudo ./bin/netdiag"
fi

if [[ $BUILD_TESTS == "ON" ]]; then
    echo "   Test programs: $BUILD_DIR/bin/"
    echo "     Run tests: cd $BUILD_DIR && ctest"
fi

echo ""
echo "Install command: cd $BUILD_DIR && sudo make install"
