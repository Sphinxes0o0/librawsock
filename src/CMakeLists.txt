# 核心库源文件
set(LIBRAWSOCK_SOURCES
    rawsock.c
    packet.c
    analyzer.c
    tcp_analyzer.c
)

# 核心库头文件
set(LIBRAWSOCK_HEADERS
    ${CMAKE_SOURCE_DIR}/include/librawsock/rawsock.h
    ${CMAKE_SOURCE_DIR}/include/librawsock/packet.h
    ${CMAKE_SOURCE_DIR}/include/librawsock/analyzer.h
    ${CMAKE_SOURCE_DIR}/include/librawsock/tcp_analyzer.h
)

# 系统依赖检查
include(CheckIncludeFile)
include(CheckFunctionExists)

check_include_file("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_file("net/if.h" HAVE_NET_IF_H)
check_include_file("ifaddrs.h" HAVE_IFADDRS_H)
check_function_exists("socket" HAVE_SOCKET)
check_function_exists("clock_gettime" HAVE_CLOCK_GETTIME)

# 配置头文件
configure_file(
    ${CMAKE_SOURCE_DIR}/include/librawsock/config.h.in
    ${CMAKE_BINARY_DIR}/include/librawsock/config.h
)

# 添加生成的配置头文件目录
include_directories(${CMAKE_BINARY_DIR}/include)

# 创建对象库（用于共享静态库和动态库的编译）
add_library(rawsock_objects OBJECT ${LIBRAWSOCK_SOURCES})

# 设置编译属性
set_target_properties(rawsock_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET default
)

# 目标包含目录
target_include_directories(rawsock_objects PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
)

# 静态库
if(BUILD_STATIC_LIBS)
    add_library(rawsock_static STATIC $<TARGET_OBJECTS:rawsock_objects>)
    set_target_properties(rawsock_static PROPERTIES
        OUTPUT_NAME rawsock
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    
    # 安装静态库
    install(TARGETS rawsock_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT static
    )
    
    # 创建别名
    add_library(librawsock::static ALIAS rawsock_static)
endif()

# 动态库
if(BUILD_SHARED_LIBS)
    add_library(rawsock_shared SHARED $<TARGET_OBJECTS:rawsock_objects>)
    set_target_properties(rawsock_shared PROPERTIES
        OUTPUT_NAME rawsock
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    
    # 链接系统库
    if(UNIX AND NOT APPLE)
        target_link_libraries(rawsock_shared rt)
    endif()
    
    # 安装动态库
    install(TARGETS rawsock_shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT shared
    )
    
    # 创建别名
    add_library(librawsock::shared ALIAS rawsock_shared)
endif()

# 创建主要目标（优先使用动态库）
if(BUILD_SHARED_LIBS)
    add_library(rawsock ALIAS rawsock_shared)
elseif(BUILD_STATIC_LIBS)
    add_library(rawsock ALIAS rawsock_static)
endif()

# 导出目标配置
if(BUILD_SHARED_LIBS OR BUILD_STATIC_LIBS)
    # 创建配置文件
    include(CMakePackageConfigHelpers)
    
    # 生成版本配置文件
    write_basic_package_version_file(
        ${CMAKE_BINARY_DIR}/librawsock-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    
    # 生成包配置文件
    configure_package_config_file(
        ${CMAKE_SOURCE_DIR}/cmake/librawsock-config.cmake.in
        ${CMAKE_BINARY_DIR}/librawsock-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/librawsock
    )
    
    # 安装配置文件
    install(FILES
        ${CMAKE_BINARY_DIR}/librawsock-config.cmake
        ${CMAKE_BINARY_DIR}/librawsock-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/librawsock
    )
endif()
