project( CryptoCL )
cmake_minimum_required( VERSION 2.8 )

# TQDLib
set( TQDLIB_DIR "" CACHE PATH "TQDLib Base Directory")
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
		find_library( OPENCL_LIB "OpenCL" )

		list( APPEND LIB_GENERAL "${TQD_OPENCL}" )
		list( APPEND LIB_GENERAL "${OPENCL_LIB}" )
	endif( BUILD_OPENCL )
endif( TQDLIB_DIR )

# Header Files
file( GLOB BASE_HEADERS include/*.h )
source_group( "include" FILES ${BASE_HEADERS} )
file( GLOB AES_HEADERS include/CryptoCL/AES/*.h )
source_group( "include\\CryptoCL\\AES" FILES ${AES_HEADERS} )

list( APPEND PROJECT_HEADERS ${BASE_HEADERS} )
list( APPEND PROJECT_HEADERS ${AES_HEADERS} )

if( NOT BUILD_OPENCL )
	list( REMOVE_ITEM PROJECT_HEADERS "${CMAKE_SOURCE_DIR}/include/CryptoCL/AES/OpenCL.h" )
endif( NOT BUILD_OPENCL )

# Source Files
file( GLOB BASE_SOURCES src/*.cpp )
source_group( "src" FILES ${BASE_SOURCES} )
file( GLOB AES_SOURCES src/CryptoCL/AES/*.cpp )
source_group( "src\\CryptoCL\\AES" FILES ${AES_SOURCES} )

list( APPEND PROJECT_SOURCES ${BASE_SOURCES} )
list( APPEND PROJECT_SOURCES ${AES_SOURCES} )

if( NOT BUILD_OPENCL )
	list( REMOVE_ITEM PROJECT_SOURCES "${CMAKE_SOURCE_DIR}/src/CryptoCL/AES/OpenCL.cpp" )
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

add_library( cryptocl STATIC ${PROJECT_SOURCES} ${PROJECT_HEADERS} )
target_link_libraries( cryptocl ${LIB_GENERAL} )

if( BUILD_SHARED )
	add_library( cryptocl-s SHARED ${PROJECT_SOURCES} ${PROJECT_HEADERS} )
	target_link_libraries( cryptocl-s ${LIB_GENERAL} )
endif( BUILD_SHARED )

# Testing
option( BUILD_TESTING "Build test code" Off )
if( BUILD_TESTING )
	# Build Program Tests
	add_subdirectory( "test" )
endif( BUILD_TESTING )

# Installation
install( DIRECTORY "include/" DESTINATION "include/" PATTERN ".svn" EXCLUDE PATTERN "*.h" )
install( TARGETS cryptocl RUNTIME DESTINATION "bin" LIBRARY DESTINATION "lib" ARCHIVE DESTINATION "lib" )

if( BUILD_SHARED )
	install( TARGETS cryptocl-s RUNTIME DESTINATION "bin" LIBRARY DESTINATION "lib" ARCHIVE DESTINATION "lib" )
endif( BUILD_SHARED )
