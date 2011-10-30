set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "../${CMAKE_SOURCE_DIR}/cmake/modules/" )

include( CopyFile )
include( Architecture )

include_directories( include )
include_directories( "../include" )

file( GLOB_RECURSE BENCHMARK_HEADERS "include/*.h" )
file( GLOB_RECURSE BENCHMARK_SOURCES "src/*.cpp" )

option( BUILD_OPENCL "Build with OpenCL" Off )
if( NOT BUILD_OPENCL )
	# list( REMOVE_ITEM TEST_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/AES/OpenCLTest.h" )
	# list( REMOVE_ITEM TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/AES/OpenCLTest.cpp" )
endif( NOT BUILD_OPENCL )

# Build
add_executable( cryptocl_benchmark main.cpp ${TEST_SOURCES} ${TEST_HEADERS} )
target_link_libraries( cryptocl_benchmark "cryptocl" )
