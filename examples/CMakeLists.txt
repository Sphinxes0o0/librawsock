# 示例程序模块
message(STATUS "Configuring example programs...")

# 示例程序源文件
set(EXAMPLE_SOURCES
    ping.c
    tcp_syn_scan.c
    packet_sniffer.c
    simple_tcp_monitor.c
    tcp_connection_analyzer.c
    demo_tcp_analysis.c
)

# 为每个示例创建独立的可执行文件
foreach(example_source ${EXAMPLE_SOURCES})
    # 从文件名提取程序名称
    get_filename_component(example_name ${example_source} NAME_WE)
    
    # 创建可执行文件
    add_executable(${example_name} ${example_source})
    
    # 链接核心库
    if(BUILD_SHARED_LIBS)
        target_link_libraries(${example_name} PRIVATE rawsock_shared)
    else()
        target_link_libraries(${example_name} PRIVATE rawsock_static)
    endif()
    
    # 设置包含目录
    target_include_directories(${example_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
    )
    
    # 设置编译选项
    target_compile_options(${example_name} PRIVATE -Wall -Wextra)
    
    # 为需要特殊权限的程序添加说明
    if(example_name MATCHES "(ping|tcp_syn_scan|packet_sniffer|.*_monitor|.*_analyzer)")
        set_target_properties(${example_name} PROPERTIES
            INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}"
            BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
        )
    endif()
    
    # 安装示例程序
    install(TARGETS ${example_name}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT examples
    )
endforeach()

# 创建示例数据目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/examples/data)

# 生成示例配置文件
configure_file(
    ${CMAKE_SOURCE_DIR}/examples/config.h.in
    ${CMAKE_BINARY_DIR}/examples/config.h
    @ONLY
)

# 添加示例配置头文件
target_include_directories(ping PRIVATE ${CMAKE_BINARY_DIR}/examples)
target_include_directories(tcp_syn_scan PRIVATE ${CMAKE_BINARY_DIR}/examples)
target_include_directories(packet_sniffer PRIVATE ${CMAKE_BINARY_DIR}/examples)

# 特殊依赖处理
# 检查 libpcap 支持（如果需要）
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP libpcap)
    if(PCAP_FOUND)
        message(STATUS "Found libpcap: ${PCAP_VERSION}")
        
        # 为需要 pcap 的示例添加支持
        target_compile_definitions(packet_sniffer PRIVATE HAVE_PCAP=1)
        target_link_libraries(packet_sniffer PRIVATE ${PCAP_LIBRARIES})
        target_include_directories(packet_sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
    else()
        message(STATUS "libpcap not found - some features may be limited")
    endif()
endif()

# TODO: 示例脚本安装暂时禁用
# 创建示例运行脚本将在后续版本中添加
message(STATUS "Example script installation skipped - will be implemented later")

# 示例文档
if(EXISTS ${CMAKE_SOURCE_DIR}/examples/README.md)
    install(FILES
        ${CMAKE_SOURCE_DIR}/examples/README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
        COMPONENT examples
    )
endif()

# 创建演示目标
add_custom_target(demo
    COMMAND echo "Available demos:"
    COMMAND echo "  ./ping 8.8.8.8"
    COMMAND echo "  sudo ./simple_tcp_monitor 10"
    COMMAND echo "  sudo ./tcp_connection_analyzer -v"
    COMMAND echo "  ./demo_tcp_analysis -d -v"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    COMMENT "Listing available demos"
)

# 快速测试目标
add_custom_target(demo_quick
    COMMAND ./demo_tcp_analysis -d
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    DEPENDS demo_tcp_analysis
    COMMENT "Running quick TCP analysis demo"
)

# 验证示例程序编译
add_custom_target(verify_examples
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/examples/verify.cmake
    DEPENDS ${EXAMPLE_SOURCES}
    COMMENT "Verifying example programs"
)
