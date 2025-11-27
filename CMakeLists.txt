cmake_minimum_required(VERSION 3.14)

project(rawsock
    VERSION 2.0.0
    DESCRIPTION "AF_PACKET based network capture library"
    LANGUAGES CXX C
)

# Options
option(RAWSOCK_BUILD_TESTS "Build unit tests" ON)
option(RAWSOCK_BUILD_EXAMPLES "Build examples" ON)
option(RAWSOCK_BUILD_SHARED "Build shared library" OFF)
option(RAWSOCK_INSTALL "Generate install target" ON)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Header-only library interface (C++ only)
add_library(rawsock_header_only INTERFACE)
target_include_directories(rawsock_header_only INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(rawsock_header_only INTERFACE cxx_std_11)

# C wrapper library
set(RAWSOCK_C_SOURCES
    src/rawsock_c.cpp
)

if(RAWSOCK_BUILD_SHARED)
    add_library(rawsock SHARED ${RAWSOCK_C_SOURCES})
    target_compile_definitions(rawsock PRIVATE RAWSOCK_SHARED_LIB RAWSOCK_BUILDING_LIB)
else()
    add_library(rawsock STATIC ${RAWSOCK_C_SOURCES})
endif()

target_include_directories(rawsock PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(rawsock PUBLIC cxx_std_11)

# Set library properties
set_target_properties(rawsock PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "include/rawsock/rawsock_c.h"
)

# Build tests
if(RAWSOCK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Build examples
if(RAWSOCK_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Install rules
if(RAWSOCK_INSTALL)
    include(GNUInstallDirs)
    
    # Install header-only library
    install(DIRECTORY include/rawsock
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
    
    # Install compiled library
    install(TARGETS rawsock rawsock_header_only
        EXPORT rawsockTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rawsock
    )
    
    # Export targets
    install(EXPORT rawsockTargets
        FILE rawsockTargets.cmake
        NAMESPACE rawsock::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rawsock
    )
    
    # Package configuration
    include(CMakePackageConfigHelpers)
    
    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/rawsockConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/rawsockConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rawsock
    )
    
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/rawsockConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/rawsockConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/rawsockConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rawsock
    )
endif()

# Uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY
    )

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
    )
endif()
