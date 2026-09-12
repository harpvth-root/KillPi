cmake_minimum_required(VERSION 3.20)
project(cppsniffer)

set(CMAKE_CXX_STANDARD 20)

# Find the pcap package on the host system
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(cppsniffer main.cpp)

# Include headers and link libpcap to your binary
target_include_directories(cppsniffer PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(cppsniffer PRIVATE ${PCAP_LIBRARIES})

