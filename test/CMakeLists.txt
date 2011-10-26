include_directories( include )
include_directories( "../include" )

# Math
file( GLOB_RECURSE TEST_HEADERS "include/*.h" )
file( GLOB_RECURSE TEST_SOURCES "src/*.cpp" )

# Build
add_executable( cryptocl_test main.cpp ${TEST_SOURCES} ${TEST_HEADERS} ${LIBRARY_HEADERS} )
target_link_libraries( cryptocl_test "cryptocl" "cppunit" ${LIBRARY_SOURCES} )
