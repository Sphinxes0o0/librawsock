# 单元测试模块
message(STATUS "Configuring unit tests...")

# 查找测试依赖
find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
    message(STATUS "Found Valgrind: ${VALGRIND_EXECUTABLE}")
    set(VALGRIND_FOUND TRUE)
else()
    message(STATUS "Valgrind not found - memory leak tests will be skipped")
    set(VALGRIND_FOUND FALSE)
endif()

# 测试通用设置
set(TEST_TIMEOUT 30)
set(TEST_WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# 测试源文件
set(TEST_SOURCES
    test_rawsock.c
    test_packet.c
    test_analyzer.c
)

# 为每个测试文件创建独立的可执行文件
foreach(test_source ${TEST_SOURCES})
    # 从文件名提取测试名称
    get_filename_component(test_name ${test_source} NAME_WE)
    
    # 创建测试可执行文件
    add_executable(${test_name} ${test_source})
    
    # 确保库先构建
    if(BUILD_SHARED_LIBS)
        add_dependencies(${test_name} rawsock_shared)
    endif()
    if(BUILD_STATIC_LIBS)
        add_dependencies(${test_name} rawsock_static)
    endif()
    
    # 链接核心库
    if(BUILD_SHARED_LIBS)
        target_link_libraries(${test_name} PRIVATE rawsock_shared)
        if(UNIX AND NOT APPLE)
            target_link_libraries(${test_name} PRIVATE rt)
        endif()
    else()
        target_link_libraries(${test_name} PRIVATE rawsock_static)
        if(UNIX AND NOT APPLE)
            target_link_libraries(${test_name} PRIVATE rt)
        endif()
    endif()
    
    # 设置包含目录
    target_include_directories(${test_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
    )
    
    # 设置编译选项
    target_compile_options(${test_name} PRIVATE -Wall -Wextra)
    
    # 添加测试
    add_test(NAME ${test_name}
        COMMAND ${test_name}
        WORKING_DIRECTORY ${TEST_WORKING_DIRECTORY}
    )
    
    # 设置测试属性
    set_tests_properties(${test_name} PROPERTIES
        TIMEOUT ${TEST_TIMEOUT}
        LABELS "unit"
    )
    
    # Valgrind 内存检查测试
    if(VALGRIND_FOUND)
        add_test(NAME ${test_name}_valgrind
            COMMAND ${VALGRIND_EXECUTABLE}
                --leak-check=full
                --show-leak-kinds=all
                --track-origins=yes
                --error-exitcode=1
                --suppressions=${CMAKE_SOURCE_DIR}/tests/valgrind.supp
                $<TARGET_FILE:${test_name}>
            WORKING_DIRECTORY ${TEST_WORKING_DIRECTORY}
        )
        
        set_tests_properties(${test_name}_valgrind PROPERTIES
            TIMEOUT $((${TEST_TIMEOUT} * 3))
            LABELS "valgrind;memory"
        )
    endif()
endforeach()

# 集成测试暂时禁用，等待实现
# TODO: 添加集成测试脚本

# 代码覆盖率支持
if(ENABLE_COVERAGE)
    find_program(GCOV_EXECUTABLE gcov)
    find_program(LCOV_EXECUTABLE lcov)
    find_program(GENHTML_EXECUTABLE genhtml)
    
    if(GCOV_EXECUTABLE AND LCOV_EXECUTABLE AND GENHTML_EXECUTABLE)
        message(STATUS "Coverage tools found - enabling coverage support")
        
        # 添加覆盖率编译选项
        foreach(test_source ${TEST_SOURCES})
            get_filename_component(test_name ${test_source} NAME_WE)
            target_compile_options(${test_name} PRIVATE --coverage)
            target_link_options(${test_name} PRIVATE --coverage)
        endforeach()
        
        # 创建覆盖率报告目标
        add_custom_target(coverage
            COMMAND ${LCOV_EXECUTABLE} --capture --directory . --output-file coverage.info
            COMMAND ${LCOV_EXECUTABLE} --remove coverage.info '/usr/*' --output-file coverage.info
            COMMAND ${LCOV_EXECUTABLE} --list coverage.info
            COMMAND ${GENHTML_EXECUTABLE} coverage.info --output-directory coverage_html
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating code coverage report"
        )
        
        # 覆盖率清理目标
        add_custom_target(coverage_clean
            COMMAND ${LCOV_EXECUTABLE} --directory . --zerocounters
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Cleaning coverage counters"
        )
    else()
        message(WARNING "Coverage tools not found - coverage support disabled")
    endif()
endif()

# 测试辅助脚本
configure_file(
    ${CMAKE_SOURCE_DIR}/tests/run_tests.sh.in
    ${CMAKE_BINARY_DIR}/run_tests.sh
    @ONLY
)

# 权限检查测试暂时禁用，等待实现
# TODO: 添加权限检查脚本

# 自定义测试目标
add_custom_target(test_unit
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L unit
    DEPENDS ${TEST_SOURCES}
    COMMENT "Running unit tests"
)

add_custom_target(test_memory
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L memory
    DEPENDS ${TEST_SOURCES}
    COMMENT "Running memory tests"
)

add_custom_target(test_all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${TEST_SOURCES}
    COMMENT "Running all tests"
)

# 安装测试数据
install(DIRECTORY data/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/librawsock/tests
    COMPONENT tests
    OPTIONAL
)
