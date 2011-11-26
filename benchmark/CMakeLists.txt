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
add_executable( cryptocl_benchmark main.cpp ${BENCHMARK_SOURCES} ${BENCHMARK_HEADERS} )
target_link_libraries( cryptocl_benchmark "cryptocl" )

# Copy files
if( BUILD_OPENCL )
	if( CMAKE_GENERATOR MATCHES "Xcode" )
		add_custom_command( 
			TARGET cryptocl_benchmark 
			COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/data/ ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/data/ 
		)
	else()
		add_custom_command( 
			TARGET cryptocl_benchmark 
			COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/data/ ${CMAKE_CURRENT_BINARY_DIR}/data/ 
		)
	endif()
endif()