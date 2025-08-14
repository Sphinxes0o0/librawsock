# Core library source files

# Source files
set(LIBRAWSOCK_SOURCES
    rawsock.c
    packet.c
    analyzer.c
    tcp_analyzer.c
)

# Core library header files
set(LIBRAWSOCK_HEADERS
    ${CMAKE_SOURCE_DIR}/include/librawsock/rawsock.h
    ${CMAKE_SOURCE_DIR}/include/librawsock/packet.h
    ${CMAKE_SOURCE_DIR}/include/librawsock/analyzer.h
    ${CMAKE_SOURCE_DIR}/include/librawsock/tcp_analyzer.h
)

# System dependency checks
include(CheckIncludeFile)
include(CheckFunctionExists)

check_include_file("netinet/ip.h" HAVE_NETINET_IP_H)
check_include_file("netinet/tcp.h" HAVE_NETINET_TCP_H)
check_function_exists(inet_pton HAVE_INET_PTON)
check_function_exists(inet_ntop HAVE_INET_NTOP)

if(NOT HAVE_NETINET_IP_H OR NOT HAVE_NETINET_TCP_H)
    message(FATAL_ERROR "Required network headers not found")
endif()

# Configure header file
configure_file(
    ${CMAKE_SOURCE_DIR}/include/librawsock/config.h.in
    ${CMAKE_BINARY_DIR}/include/librawsock/config.h
    @ONLY
)

# Add generated config header directory
target_include_directories(rawsock_obj INTERFACE
    ${CMAKE_BINARY_DIR}/include
)

# Create object library (for shared static and dynamic library compilation)
add_library(rawsock_obj OBJECT ${LIBRAWSOCK_SOURCES})

# Set compilation properties
target_compile_features(rawsock_obj PUBLIC c_std_99)
target_compile_options(rawsock_obj PRIVATE
    -Wall -Wextra -fPIC
    $<$<CONFIG:Debug>:-g -O0 -DDEBUG>
    $<$<CONFIG:Release>:-O2 -DNDEBUG>
)

# Target include directories
target_include_directories(rawsock_obj PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
)

# Static library
if(BUILD_STATIC_LIBS)
    add_library(rawsock_static STATIC $<TARGET_OBJECTS:rawsock_obj>)

    set_target_properties(rawsock_static PROPERTIES
        OUTPUT_NAME rawsock
        POSITION_INDEPENDENT_CODE ON
    )

    # Install static library
    install(TARGETS rawsock_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT static
    )

    # Create alias
    add_library(rawsock::static ALIAS rawsock_static)
endif()

# Dynamic library
if(BUILD_SHARED_LIBS)
    add_library(rawsock_shared SHARED $<TARGET_OBJECTS:rawsock_obj>)

    set_target_properties(rawsock_shared PROPERTIES
        OUTPUT_NAME rawsock
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        POSITION_INDEPENDENT_CODE ON
    )

    # Link system libraries
    target_link_libraries(rawsock_shared PRIVATE
        ${CMAKE_THREAD_LIBS_INIT}
        m  # math library
    )

    # Install dynamic library
    install(TARGETS rawsock_shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT shared
    )

    # Create alias
    add_library(rawsock::shared ALIAS rawsock_shared)
endif()

# Create main target (prefer dynamic library)
if(BUILD_SHARED_LIBS)
    add_library(rawsock ALIAS rawsock_shared)
else()
    add_library(rawsock ALIAS rawsock_static)
endif()
