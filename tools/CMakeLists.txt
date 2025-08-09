# 开发工具模块
message(STATUS "Configuring development tools...")

# 检查工具目录是否存在源文件
file(GLOB TOOL_SOURCES "*.c")
file(GLOB TOOL_SCRIPTS "*.sh")

# C/C++ 工具程序
if(TOOL_SOURCES)
    foreach(tool_source ${TOOL_SOURCES})
        # 从文件名提取工具名称
        get_filename_component(tool_name ${tool_source} NAME_WE)
        
        # 创建工具可执行文件
        add_executable(${tool_name} ${tool_source})
        
        # 链接核心库
        if(BUILD_SHARED_LIBS)
            target_link_libraries(${tool_name} PRIVATE rawsock_shared)
        else()
            target_link_libraries(${tool_name} PRIVATE rawsock_static)
        endif()
        
        # 设置包含目录
        target_include_directories(${tool_name} PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_BINARY_DIR}/include
        )
        
        # 优化编译选项（工具程序需要更好的性能）
        target_compile_options(${tool_name} PRIVATE
            -Wall -Wextra -O2
            $<$<CONFIG:Debug>:-g -O0>
            $<$<CONFIG:Release>:-DNDEBUG>
        )
        
        # 设置 RPATH
        set_target_properties(${tool_name} PROPERTIES
            INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}"
            BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
        )
        
        # 安装工具
        install(TARGETS ${tool_name}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT tools
        )
        
        message(STATUS "Added tool: ${tool_name}")
    endforeach()
endif()

# 脚本工具 (暂时禁用脚本安装以避免配置问题)
# TODO: 添加脚本配置和安装逻辑
message(STATUS "Script installation skipped - will be implemented later")

# 上面的自动发现已经处理了所有工具，这里不需要重复

# Python 工具（如果存在）
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    file(GLOB PYTHON_TOOLS ${CMAKE_SOURCE_DIR}/tools/*.py)
    
    foreach(py_tool ${PYTHON_TOOLS})
        get_filename_component(py_name ${py_tool} NAME)
        
        configure_file(
            ${py_tool}
            ${CMAKE_BINARY_DIR}/tools/${py_name}
            @ONLY
            FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                            GROUP_READ GROUP_EXECUTE
                            WORLD_READ WORLD_EXECUTE
        )
        
        install(FILES ${CMAKE_BINARY_DIR}/tools/${py_name}
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT tools
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                       GROUP_READ GROUP_EXECUTE
                       WORLD_READ WORLD_EXECUTE
        )
    endforeach()
endif()

# 工具文档
if(EXISTS ${CMAKE_SOURCE_DIR}/tools/README.md)
    install(FILES
        ${CMAKE_SOURCE_DIR}/tools/README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/tools
        COMPONENT tools
    )
endif()

# 创建工具测试目标
add_custom_target(test_tools
    COMMAND ${CMAKE_COMMAND} -E echo "Tool testing - implementation pending"
    COMMENT "Testing development tools"
)

# 性能基准目标
add_custom_target(run_benchmarks
    COMMAND ./benchmark --all
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    COMMENT "Running performance benchmarks"
)

# 网络诊断目标
add_custom_target(run_netdiag
    COMMAND ./netdiag --check-all
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    COMMENT "Running network diagnostics"
)
