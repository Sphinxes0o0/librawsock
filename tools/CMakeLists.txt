# Development tools module

# Check if tool directory has source files
if(NOT TOOL_SOURCES)
    return()
endif()

# C/C++ tool programs
foreach(TOOL_SOURCE ${TOOL_SOURCES})
    # Extract tool name from filename
    get_filename_component(TOOL_NAME ${TOOL_SOURCE} NAME_WE)

    # Create tool executable
    add_executable(${TOOL_NAME} ${TOOL_SOURCE})

    # Link core library
    target_link_libraries(${TOOL_NAME} rawsock)

    # Set output directory
    set_target_properties(${TOOL_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

    # Set include directories
    target_include_directories(${TOOL_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    # Optimization compilation options (tool programs need better performance)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(${TOOL_NAME} PRIVATE -O3)
    endif()

    # Set RPATH
    set_target_properties(${TOOL_NAME} PROPERTIES
        INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib"
        BUILD_WITH_INSTALL_RPATH TRUE
    )

    # Install tools
    install(TARGETS ${TOOL_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endforeach()

# Script tools (temporarily disable script installation to avoid configuration issues)
# TODO: Add script configuration and installation logic

# Python tools (if they exist)
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

# Tool documentation
if(EXISTS ${CMAKE_SOURCE_DIR}/tools/README.md)
    install(FILES
        ${CMAKE_SOURCE_DIR}/tools/README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/tools
        COMPONENT tools
    )
endif()

# Create tool test target
add_custom_target(test_tools
    COMMAND ${CMAKE_COMMAND} -E echo "Tool testing - implementation pending"
    COMMENT "Testing development tools"
)

# Performance benchmark target
add_custom_target(run_benchmarks
    COMMAND ./benchmark --all
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    COMMENT "Running performance benchmarks"
)

# Network diagnostic target
add_custom_target(run_netdiag
    COMMAND ./netdiag --check-all
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    COMMENT "Running network diagnostics"
)
