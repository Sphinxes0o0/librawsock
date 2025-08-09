cmake_minimum_required(VERSION 3.10)
project(librawsock VERSION 1.0.0 LANGUAGES C)

# 设置 C 标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# 默认构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 项目选项
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_STATIC_LIBS "Build static libraries" ON)
option(BUILD_TESTS "Build unit tests" OFF)
option(BUILD_EXAMPLES "Build example programs" OFF)
option(BUILD_TOOLS "Build development tools" OFF)
option(ENABLE_COVERAGE "Enable test coverage" OFF)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# 添加核心库
add_subdirectory(src)

# 可选模块
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# 安装配置
include(GNUInstallDirs)

# 安装头文件
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# 生成 pkg-config 文件
configure_file(
    ${CMAKE_SOURCE_DIR}/librawsock.pc.in
    ${CMAKE_BINARY_DIR}/librawsock.pc
    @ONLY
)

install(FILES ${CMAKE_BINARY_DIR}/librawsock.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# CPack 配置
set(CPACK_PACKAGE_NAME "librawsock")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Raw Socket Network Library with TCP Protocol Analysis")
set(CPACK_PACKAGE_VENDOR "LibRawSock Team")
set(CPACK_PACKAGE_CONTACT "librawsock@example.com")
set(CPACK_GENERATOR "TGZ;DEB")

include(CPack)

# 显示配置信息
message(STATUS "")
message(STATUS "========== LibRawSock Build Configuration ==========")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C flags: ${CMAKE_C_FLAGS}")
message(STATUS "")
message(STATUS "Build options:")
message(STATUS "  Shared libraries: ${BUILD_SHARED_LIBS}")
message(STATUS "  Static libraries: ${BUILD_STATIC_LIBS}")
message(STATUS "  Unit tests: ${BUILD_TESTS}")
message(STATUS "  Examples: ${BUILD_EXAMPLES}")
message(STATUS "  Tools: ${BUILD_TOOLS}")
message(STATUS "  Coverage: ${ENABLE_COVERAGE}")
message(STATUS "")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "===================================================")
message(STATUS "")
