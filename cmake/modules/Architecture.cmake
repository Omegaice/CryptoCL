if( NOT MSVC )
	option( ARCH_64 "Compile for 64bit architectures." Off )
	if( ARCH_64 )
		if( NOT CMAKE_CXX_FLAGS MATCHES ".*-m64.*" )
			set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64" )
		endif()
		
		if( NOT CMAKE_EXE_LINKER_FLAGS MATCHES ".*-m64.*" )
			set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64" )
		endif()
		
		if( NOT CMAKE_SHARED_LINKER_FLAGS MATCHES ".*-m64.*" )
			set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m64" )
		endif()
		
		# Add 64bit debug warnings
		#if( NOT CMAKE_CXX_FLAGS_DEBUG MATCHES ".*-Wconversion -Wshorten-64-to-32.*" )
		#	set( CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wconversion -Wshorten-64-to-32" )
		#endif()
	else( )
		if( NOT CMAKE_CXX_FLAGS MATCHES ".*-m32.*" )
			set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" )
		endif()
		
		if( NOT CMAKE_EXE_LINKER_FLAGS MATCHES ".*-m32.*" )
			set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32" )
		endif()
		
		if( NOT CMAKE_SHARED_LINKER_FLAGS MATCHES ".*-m32.*" )
			set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32" )
		endif()
	endif( )
endif( )
