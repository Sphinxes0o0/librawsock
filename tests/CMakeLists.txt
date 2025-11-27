cmake_minimum_required(VERSION 3.14)

# Unit tests for rawsock library

enable_testing()

# Packet parsing tests
add_executable(test_packet test_packet.cpp)
target_link_libraries(test_packet PRIVATE rawsock)
add_test(NAME test_packet COMMAND test_packet)

# Error handling tests
add_executable(test_error test_error.cpp)
target_link_libraries(test_error PRIVATE rawsock)
add_test(NAME test_error COMMAND test_error)

# Capture tests
add_executable(test_capture test_capture.cpp)
target_link_libraries(test_capture PRIVATE rawsock)
add_test(NAME test_capture COMMAND test_capture)

# C interface tests
add_executable(test_c_interface test_c_interface.cpp)
target_link_libraries(test_c_interface PRIVATE rawsock)
add_test(NAME test_c_interface COMMAND test_c_interface)

# Simple test runner that doesn't require privileges
add_executable(rawsock_basic_tests test_basic.cpp)
target_link_libraries(rawsock_basic_tests PRIVATE rawsock)
add_test(NAME rawsock_basic_tests COMMAND rawsock_basic_tests)

# Privilege check test (can run without root)
add_executable(rawsock_privilege_test test_privilege.cpp)
target_link_libraries(rawsock_privilege_test PRIVATE rawsock)
add_test(NAME rawsock_privilege_test COMMAND rawsock_privilege_test)
