cmake_minimum_required(VERSION 3.10)
project(librawsock VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build options
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_STATIC_LIBS "Build static library" ON)

# Core library source files
set(LIBRAWSOCK_SOURCES
    src/rawsock.c
    src/packet.c
)

set(LIBRAWSOCK_HEADERS
    include/rawsock.h
    include/packet.h
)

# Configure header file
configure_file(
    include/config.h.in
    ${CMAKE_BINARY_DIR}/include/config.h
    @ONLY
)

# Create library
add_library(rawsock ${LIBRAWSOCK_SOURCES})

# Set properties
set_target_properties(rawsock PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME rawsock
    POSITION_INDEPENDENT_CODE ON
)

# Include directories
target_include_directories(rawsock PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
)

# Compile options
target_compile_options(rawsock PRIVATE -Wall -Wextra)

# Copy headers to build directory for easy access
add_custom_command(TARGET rawsock POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/include
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/include/rawsock.h ${CMAKE_BINARY_DIR}/include/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/include/packet.h ${CMAKE_BINARY_DIR}/include/
    COMMENT "Copying headers to build directory"
)

# Install configuration
include(GNUInstallDirs)

# Install library
install(TARGETS rawsock
    EXPORT librawsock-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(FILES ${LIBRAWSOCK_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install pkg-config file
configure_file(librawsock.pc.in librawsock.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/librawsock.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
