message(STATUS "Configuring example programs...")

set(EXAMPLE_SOURCES
    ping.c
    tcp_syn_scan.c
    packet_sniffer.c
    simple_tcp_monitor.c
    tcp_connection_analyzer.c
    demo_tcp_analysis.c
)

foreach(example_source ${EXAMPLE_SOURCES})
    get_filename_component(example_name ${example_source} NAME_WE)
    add_executable(${example_name} ${example_source})

    if(BUILD_SHARED_LIBS)
        target_link_libraries(${example_name} PRIVATE rawsock_shared)
    else()
        target_link_libraries(${example_name} PRIVATE rawsock_static)
    endif()

    target_include_directories(${example_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
    )

    target_compile_options(${example_name} PRIVATE -Wall -Wextra)

    if(example_name MATCHES "(ping|tcp_syn_scan|packet_sniffer|.*_monitor|.*_analyzer)")
        set_target_properties(${example_name} PROPERTIES
            INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}"
            BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
        )
    endif()

    install(TARGETS ${example_name}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT examples
    )
endforeach()

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/examples/data)

configure_file(
    ${CMAKE_SOURCE_DIR}/examples/config.h.in
    ${CMAKE_BINARY_DIR}/examples/config.h
    @ONLY
)

target_include_directories(ping PRIVATE ${CMAKE_BINARY_DIR}/examples)
target_include_directories(tcp_syn_scan PRIVATE ${CMAKE_BINARY_DIR}/examples)
target_include_directories(packet_sniffer PRIVATE ${CMAKE_BINARY_DIR}/examples)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP libpcap)
    if(PCAP_FOUND)
        message(STATUS "Found libpcap: ${PCAP_VERSION}")

        target_compile_definitions(packet_sniffer PRIVATE HAVE_PCAP=1)
        target_link_libraries(packet_sniffer PRIVATE ${PCAP_LIBRARIES})
        target_include_directories(packet_sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
    else()
        message(STATUS "libpcap not found - some features may be limited")
    endif()
endif()

message(STATUS "Example script installation skipped - will be implemented later")

if(EXISTS ${CMAKE_SOURCE_DIR}/examples/README.md)
    install(FILES
        ${CMAKE_SOURCE_DIR}/examples/README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
        COMPONENT examples
    )
endif()

add_custom_target(demo
    COMMAND echo "Available demos:"
    COMMAND echo "  ./ping 8.8.8.8"
    COMMAND echo "  sudo ./simple_tcp_monitor 10"
    COMMAND echo "  sudo ./tcp_connection_analyzer -v"
    COMMAND echo "  ./demo_tcp_analysis -d -v"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    COMMENT "Listing available demos"
)

add_custom_target(demo_quick
    COMMAND ./demo_tcp_analysis -d
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    DEPENDS demo_tcp_analysis
    COMMENT "Running quick TCP analysis demo"
)

add_custom_target(verify_examples
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/examples/verify.cmake
    DEPENDS ${EXAMPLE_SOURCES}
    COMMENT "Verifying example programs"
)
