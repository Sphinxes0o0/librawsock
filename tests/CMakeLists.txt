# Unit test module

# Find test dependencies
find_package(Threads REQUIRED)

# Check for Valgrind
find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
    set(HAVE_VALGRIND TRUE)
    message(STATUS "Found Valgrind: ${VALGRIND_EXECUTABLE}")
endif()

# Test common settings
enable_testing()

# Test source files
file(GLOB TEST_SOURCES "*.c")
if(NOT TEST_SOURCES)
    message(WARNING "No test sources found in tests directory")
    return()
endif()

# Create separate executable for each test file
foreach(TEST_SOURCE ${TEST_SOURCES})
    # Extract test name from filename
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)

    # Create test executable
    add_executable(${TEST_NAME} ${TEST_SOURCE})

    # Ensure library is built first
    add_dependencies(${TEST_NAME} rawsock)

    # Link core library
    if(BUILD_SHARED_LIBS)
        target_link_libraries(${TEST_NAME} PRIVATE rawsock_shared)
    else()
        target_link_libraries(${TEST_NAME} PRIVATE rawsock_static)
    endif()

    # Link test dependencies
    target_link_libraries(${TEST_NAME} PRIVATE
        ${CMAKE_THREAD_LIBS_INIT}
        m  # math library
    )

    # Set include directories
    target_include_directories(${TEST_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests
    )

    # Set compilation options
    target_compile_options(${TEST_NAME} PRIVATE -Wall -Wextra)

    # Add test
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})

    # Set test properties
    set_tests_properties(${TEST_NAME} PROPERTIES
        TIMEOUT 300
        ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
    )

    # Valgrind memory check tests
    if(HAVE_VALGRIND)
        add_test(NAME ${TEST_NAME}_valgrind 
                 COMMAND ${VALGRIND_EXECUTABLE} 
                 --tool=memcheck 
                 --leak-check=full 
                 --show-leak-kinds=all 
                 --track-origins=yes 
                 --verbose 
                 --log-file=${CMAKE_BINARY_DIR}/valgrind_${TEST_NAME}.log 
                 ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME})

        set_tests_properties(${TEST_NAME}_valgrind PROPERTIES
            TIMEOUT 600
            LABELS "valgrind"
            ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
        )
    endif()

    message(STATUS "Added test: ${TEST_NAME}")
endforeach()

# Integration tests temporarily disabled, waiting for implementation

# Code coverage support
if(ENABLE_COVERAGE)
    find_program(GCOV_EXECUTABLE gcov)
    find_program(LCOV_EXECUTABLE lcov)
    find_program(GENHTML_EXECUTABLE genhtml)

    if(GCOV_EXECUTABLE AND LCOV_EXECUTABLE AND GENHTML_EXECUTABLE)
        message(STATUS "Coverage tools found - enabling coverage support")

        # Add coverage compilation options
        foreach(TEST_SOURCE ${TEST_SOURCES})
            get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
            target_compile_options(${TEST_NAME} PRIVATE --coverage)
            target_link_options(${TEST_NAME} PRIVATE --coverage)
        endforeach()

        # Create coverage report target
        add_custom_target(coverage
            COMMAND ${LCOV_EXECUTABLE} --capture --directory . --output-file coverage.info
            COMMAND ${LCOV_EXECUTABLE} --remove coverage.info '/usr/*' --output-file coverage.info
            COMMAND ${LCOV_EXECUTABLE} --list coverage.info
            COMMAND ${GENHTML_EXECUTABLE} coverage.info --output-directory coverage_html
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating code coverage report"
        )

        # Coverage cleanup target
        add_custom_target(coverage_clean
            COMMAND ${LCOV_EXECUTABLE} --directory . --zerocounters
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Cleaning coverage counters"
        )
    else()
        message(WARNING "Coverage tools not found - coverage support disabled")
    endif()
endif()

# Test helper scripts
configure_file(
    ${CMAKE_SOURCE_DIR}/tests/run_tests.sh.in
    ${CMAKE_BINARY_DIR}/run_tests.sh
    @ONLY
)

# Permission check tests temporarily disabled, waiting for implementation

# Custom test targets
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

# Install test data
install(DIRECTORY data/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/librawsock/tests
    COMPONENT tests
    OPTIONAL
)
