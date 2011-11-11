project( CryptoCL )
cmake_minimum_required( VERSION 2.8 )

set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/" )

include( CopyFile )
include( Architecture )

# TQDLib
set( TQDLIB_DIR "$ENV{TQDLIB_HOME}" CACHE PATH "TQDLib Base Directory")
if( TQDLIB_DIR )
    # Setup definition for compilation
	if( MSVC )
		add_definitions( "-DMSVC" )
	endif( MSVC )

	# Add directory to compile paths
	include_directories( "${TQDLIB_DIR}/include/" )

	option( BUILD_OPENCL "Build with OpenCL" Off )
	if( BUILD_OPENCL )
		find_library( TQD_OPENCL "tqdlib-compute-opencl-s" HINT "${TQDLIB_DIR}/lib/" )
		find_library( OPENCL_LIB "OpenCL" HINT $ENV{OPENCL_HOME} )

		list( APPEND LIB_GENERAL "${TQD_OPENCL}" )
		list( APPEND LIB_GENERAL "${OPENCL_LIB}" )
	endif( BUILD_OPENCL )
endif( TQDLIB_DIR )

# Header Files
file( GLOB BASE_HEADERS include/CryptoCL/*.h )
source_group( "include" FILES ${BASE_HEADERS} )
file( GLOB BLOCK_HEADERS include/CryptoCL/Block/*.h )
source_group( "include\\CryptoCL\\Block" FILES ${BLOCK_HEADERS} )
file( GLOB BLOCK_AES_HEADERS include/CryptoCL/Block/AES/*.h )
source_group( "include\\CryptoCL\\Block\\AES" FILES ${BLOCK_AES_HEADERS} )

list( APPEND PROJECT_HEADERS ${BASE_HEADERS} )
list( APPEND PROJECT_HEADERS ${BLOCK_HEADERS} )
list( APPEND PROJECT_HEADERS ${BLOCK_AES_HEADERS} )

if( NOT BUILD_OPENCL )
	list( REMOVE_ITEM PROJECT_HEADERS "${CMAKE_SOURCE_DIR}/include/CryptoCL/Block/AES/OpenCL.h" )
endif( NOT BUILD_OPENCL )

# Source Files
file( GLOB BASE_SOURCES src/*.cpp )
source_group( "src" FILES ${BASE_SOURCES} )
file( GLOB AES_SOURCES src/CryptoCL/AES/*.cpp )
source_group( "src\\CryptoCL\\AES" FILES ${AES_SOURCES} )

file( GLOB BASE_SOURCES src/CryptoCL/*.cpp )
source_group( "src" FILES ${BASE_SOURCES} )
file( GLOB BLOCK_SOURCES src/CryptoCL/Block/*.cpp )
source_group( "src\\CryptoCL\\Block" FILES ${BLOCK_SOURCES} )
file( GLOB BLOCK_AES_SOURCES src/CryptoCL/Block/AES/*.cpp )
source_group( "src\\CryptoCL\\Block\\AES" FILES ${BLOCK_AES_SOURCES} )

list( APPEND PROJECT_SOURCES ${BASE_SOURCES} )
list( APPEND PROJECT_SOURCES ${BLOCK_SOURCES} )
list( APPEND PROJECT_SOURCES ${BLOCK_AES_SOURCES} )

if( NOT BUILD_OPENCL )
	list( REMOVE_ITEM PROJECT_SOURCES "${CMAKE_SOURCE_DIR}/src/CryptoCL/Block/AES/OpenCL.cpp" )
endif( NOT BUILD_OPENCL )

# Data Files
file( GLOB BASE_DATA data/*.cl )
source_group( "data" FILES ${BASE_DATA} )

set( PROJECT_DATA ${BASE_DATA} )

# Code Coverage
option( CODE_COVERAGE "Build library with code coverage instrumentation" Off )
if( CODE_COVERAGE )
	set( COVERAGE_COMMAND "gcov" )

	set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage" )
	set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage" )
	set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage" )

	set( CMAKE_CXX_STANDARD_LIBRARIES "-lgcov" )
endif( CODE_COVERAGE )

# Compilation
include_directories( "include" )

add_library( cryptocl STATIC ${PROJECT_SOURCES} ${PROJECT_HEADERS} ${PROJECT_DATA} )
target_link_libraries( cryptocl ${LIB_GENERAL} )

if( BUILD_SHARED )
	add_library( cryptocl-s SHARED ${PROJECT_SOURCES} ${PROJECT_HEADERS} ${PROJECT_DATA} )
	target_link_libraries( cryptocl-s ${LIB_GENERAL} )
endif( BUILD_SHARED )

# Testing
option( BUILD_TESTING "Build test code" Off )
if( BUILD_TESTING )
	add_subdirectory( "test" )
endif( BUILD_TESTING )

# MemTest
option( BUILD_MEM_TESTING "Build memory test code" Off )
if( BUILD_MEM_TESTING )
	add_subdirectory( "memtest" )
endif( BUILD_MEM_TESTING )

# Testing
option( BUILD_BENCHMARK "Build benchmark code" Off )
if( BUILD_BENCHMARK )
	add_subdirectory( "benchmark" )
endif( BUILD_BENCHMARK )

# Installation
install( DIRECTORY "include/" DESTINATION "include/" PATTERN ".svn" EXCLUDE PATTERN "*.h" )
install( TARGETS cryptocl RUNTIME DESTINATION "bin" LIBRARY DESTINATION "lib" ARCHIVE DESTINATION "lib" )

if( BUILD_SHARED )
	install( TARGETS cryptocl-s RUNTIME DESTINATION "bin" LIBRARY DESTINATION "lib" ARCHIVE DESTINATION "lib" )
endif( BUILD_SHARED )
