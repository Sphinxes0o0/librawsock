#!/bin/bash

# Simple build script for librawsock
set -e

echo "Building librawsock..."

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
make -j$(nproc)

echo "Build completed!"
echo "Library files: build/"
echo "Headers: build/include/"
echo ""
echo "Usage:"
echo "  gcc -Ibuild/include -Lbuild -lrawsock your_program.c -o your_program"
