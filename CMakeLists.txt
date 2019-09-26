# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
# for a Realworld-Exampel see e.g.:
#	https://github.com/Microsoft/onnxruntime/blob/master/cmake/CMakeLists.txt
#
cmake_minimum_required (VERSION 3.8)

project ("IPPerfTest")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

#add_compile_definitions(RIOSINGELQUEUEMODE)
add_definitions(-DNRIOSINGELQUEUEMODE)

#include_directories(
#  ${ONNXRUNTIME_INCLUDE_DIR} 
#  ${REPO_ROOT}/include/onnxruntime/core/session
#)

# CMAKE_BUILD_TYPE == { Release, Debug, RelWithDebInfo, MinSizeRel } 
#CMAKE_BUILD_TYPE:STRING=MinSizeRel

# NOTE: POSITION INDEPENDENT CODE hurts performance, and it only make sense on POSIX systems
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(MSVC_STATIC_RUNTIME "Compile for the static CRT" OFF)
option(USE_JEMALLOC "Use jecmalloc" OFF)
option(USE_MP "Multi-Processor Compatible" ON)
option(USE_SECCHECKS "Enable Securitychecks for Compile-Flags" OFF)

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Build type not set - using MinSizeRel")
  set(CMAKE_BUILD_TYPE "MinSizeRel" CACHE STRING "Choose build type: Debug Release MinSizeRel RelWithDebInfo." FORCE)
endif()

if (USE_JEMALLOC)
  if (Win32)
    message( FATAL_ERROR "Jemalloc is not supported on Windows." )
  endif()
  include(jemalloc)
  add_definitions(-DUSE_JEMALLOC=1)
  list(APPEND EXTERNAL_LIBRARIES ${JEMALLOC_STATIC_LIBRARIES})
  list(APPEND EXTERNAL_DEPENDENCIES jemalloc)
endif()

if (MSVC)
  if (MSVC_STATIC_RUNTIME)
    # set all of our submodules to static runtime
    set(USE_MSVC_STATIC_RUNTIME ON)
    set(protobuf_MSVC_STATIC_RUNTIME ON)
    set(gtest_force_shared_crt OFF)

    # In case we are building static libraries, link also the runtime library statically
    # so that MSVCR*.DLL is not required at runtime.
    # https://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx
    # This is achieved by replacing msvc option /MD with /MT and /MDd with /MTd
    # https://gitlab.kitware.com/cmake/community/wikis/FAQ#how-can-i-build-my-msvc-application-with-a-static-runtime
    foreach(flag_var
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
      if(${flag_var} MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
      endif(${flag_var} MATCHES "/MD")
    endforeach(flag_var)
  else()
    set(USE_MSVC_STATIC_RUNTIME OFF)
    set(protobuf_WITH_ZLIB  OFF CACHE BOOL "" FORCE)
    set(protobuf_MSVC_STATIC_RUNTIME OFF CACHE BOOL "Link protobuf to static runtime libraries" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "Use shared (DLL) run-time lib for gtest" FORCE)
  endif()
  #MP
  if(USE_MP)
	SET (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MP")
	SET (CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} /MP")
  endif()

  #Compile-Optimization
  #1st remove /O0, /O1, ...
  foreach(flag_var
        CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_MINSIZEREL)
			string(REGEX REPLACE "/O[0123it]" "" ${flag_var} "${${flag_var}}")
			string(REGEX REPLACE "/Ob[0-9]" "" ${flag_var} "${${flag_var}}")
    endforeach(flag_var)
  #2nd set the new C_FLAGS
  SET (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Oi /Ot /GL")
  SET (CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} /O2 /Oi /Ot /GL")

  if(USE_SECCHECKS)
    SET (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GS")
	SET (CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} /GS")
  else()
	SET (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GS-")
	SET (CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} /GS-")
  endif()

  #Always enable exception handling, even for Windows ARM
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
  #Disable 4100 globally. Too many this kind errors in protobuf
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4100")

  if (NOT USE_CUDA)
    SET (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Gw /GL")
	SET (CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} /Gw /GL")
    SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /Gw /GL")
  endif()
  #check_cxx_compiler_flag(-Qspectre HAS_QSPECTRE)

  if (HAS_QSPECTRE)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Qspectre")
  endif()
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} /DYNAMICBASE")
  #check_cxx_compiler_flag(-guard:cf HAS_GUARD_CF)

  if (HAS_GUARD_CF)
    SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /guard:cf")
    SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /guard:cf")
	SET(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_RELEASE} /guard:cf")
	SET(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_RELEASE} /guard:cf")
    SET(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} /guard:cf")
    SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /guard:cf")
    SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} /guard:cf")
  endif()
else()
  if(BUILD_FOR_NATIVE_MACHINE)
    string(APPEND CMAKE_CXX_FLAGS_RELEASE " -march=native -mtune=native")
    string(APPEND CMAKE_C_FLAGS_RELEASE " -march=native -mtune=native")
	string(APPEND CMAKE_CXX_FLAGS_MINSIZEREL " -march=native -mtune=native")
	string(APPEND CMAKE_C_FLAGS_MINSIZEREL " -march=native -mtune=native")
    string(APPEND CMAKE_CXX_FLAGS_RELWITHDEBINFO " -march=native -mtune=native")
    string(APPEND CMAKE_C_FLAGS_RELWITHDEBINFO " -march=native -mtune=native")
  endif()

  if(BUILD_x86)
    set (CMAKE_SYSTEM_PROCESSOR "x86")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse2 -mfpmath=sse -Wno-narrowing")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse2 -mfpmath=sse -Wno-narrowing")
  endif()

  #Options for Linker
#  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:X64 /OPT:REF /OPT:ICF /INCREMENTAL:NO")
endif()

#COMPILE_FLAGS
#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
#set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
#	or
#string(APPEND CMAKE_C_FLAGS "-O3")

#set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
#set (CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} /O2")
#set (CMAKE_LINK_FLAGS_MINSIZEREL "-O3")

# Include sub-projects.
add_subdirectory ("IPPerfTest")
