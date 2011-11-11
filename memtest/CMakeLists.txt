include_directories( "../include" )

# Build
add_executable( cryptocl_mem_test main.cpp )
target_link_libraries( cryptocl_mem_test "cryptocl" )

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
