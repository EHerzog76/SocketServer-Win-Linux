# CMakeList.txt : CMake project for IPPerfTest, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

add_library(PThread STATIC "Win32_PThread.c")
add_library(WIN32API STATIC "Win32_APIs.c")