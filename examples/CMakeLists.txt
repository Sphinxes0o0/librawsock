cmake_minimum_required(VERSION 3.14)

# Examples for rawsock library

# C++ example - packet capture
add_executable(capture_example capture_example.cpp)
target_link_libraries(capture_example PRIVATE rawsock)

# C example - packet capture
add_executable(capture_example_c capture_example.c)
target_link_libraries(capture_example_c PRIVATE rawsock)

# Simple demo
add_executable(simple_demo simple_demo.cpp)
target_link_libraries(simple_demo PRIVATE rawsock)
