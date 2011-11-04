set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "../${CMAKE_SOURCE_DIR}/cmake/modules/" )
include( Architecture )

# CPPUnit
set( CPPUNIT_DIR "$ENV{CPPUNIT_HOME}" CACHE PATH "CPPUnit Base Directory")
if( CPPUNIT_DIR )
	link_directories( "${CPPUNIT_DIR}/lib/" )
	include_directories( "${CPPUNIT_DIR}/include/" )
endif( CPPUNIT_DIR )

find_library( CPPUNIT_LIB "cppunit" HINT "${CPPUNIT_DIR}" )

# Sources
include_directories( include )
include_directories( "../include" )

file( GLOB_RECURSE TEST_HEADERS "include/*.h" )
file( GLOB_RECURSE TEST_SOURCES "src/*.cpp" )

option( BUILD_OPENCL "Build with OpenCL" Off )
if( NOT BUILD_OPENCL )
	list( REMOVE_ITEM TEST_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/AES/OpenCLTest.h" )
	list( REMOVE_ITEM TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/AES/OpenCLTest.cpp" )
endif( NOT BUILD_OPENCL )

# Build
add_executable( cryptocl_test main.cpp ${TEST_SOURCES} ${TEST_HEADERS} ${LIBRARY_HEADERS} )
target_link_libraries( cryptocl_test "cryptocl" ${CPPUNIT_LIB} )

# Copy files
if( BUILD_OPENCL )
	if( CMAKE_GENERATOR MATCHES "Xcode" )
		add_custom_command( 
			TARGET cryptocl_test 
			COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/data/ ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/data/ 
		)
	else()
		add_custom_command( 
			TARGET cryptocl_test 
			COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/data/ ${CMAKE_CURRENT_BINARY_DIR}/data/ 
		)
	endif()
endif()