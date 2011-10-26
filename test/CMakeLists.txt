include_directories( include )
include_directories( "../include" )

file( GLOB_RECURSE TEST_HEADERS "include/*.h" )
file( GLOB_RECURSE TEST_SOURCES "src/*.cpp" )

if( NOT BUILD_OPENCL )
	list( REMOVE_ITEM TEST_HEADERS "${CMAKE_SOURCE_DIR}/include/AES/OpenCLTest.h" )
	list( REMOVE_ITEM TEST_SOURCES "${CMAKE_SOURCE_DIR}/src/AES/OpenCLTest.cpp" )
endif( NOT BUILD_OPENCL )

# Build
add_executable( cryptocl_test main.cpp ${TEST_SOURCES} ${TEST_HEADERS} ${LIBRARY_HEADERS} )
target_link_libraries( cryptocl_test "cryptocl" "cppunit" ${LIBRARY_SOURCES} )
