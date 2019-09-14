# CMakeList.txt : CMake project for IPPerfTest, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}\\Win32_Interop)

add_subdirectory ("Win32_Interop")

add_library(STRLCPY STATIC "strlcpy.c")
add_library(UTIL STATIC "util.c")
add_library(NETADDR STATIC "addr.c")
add_library(GETOPT STATIC "getopt_long.c")
add_library(TOMMYDS STATIC "tommyhash.c" "tommylist.c" "tommyhashlin.c")

# Add source to this project's executable.
#add_executable (IPPerfTest "IPPerfTest.cpp" "IPPerfTest.h")
add_executable (IPPerfTest "IPPerfTest.c")
target_link_libraries(IPPerfTest PThread)
target_link_libraries(IPPerfTest STRLCPY)
target_link_libraries(IPPerfTest UTIL)
target_link_libraries(IPPerfTest NETADDR)
target_link_libraries(IPPerfTest WIN32API)
target_link_libraries(IPPerfTest GETOPT)
target_link_libraries(IPPerfTest TOMMYDS)

# TODO: Add tests and install targets if needed.
#install (TARGETS IPPerfTest DESTINATION IPPerfTest/bin)
