function( CopyFiles TRG FILES DESTINATION)
  foreach( FILE ${FILES})
    set( SRC "${CMAKE_CURRENT_SOURCE_DIR}/${FILE}" )
    set( DST "${DESTINATION}/${FILE}" )

    add_custom_command( 
		TARGET ${TRG} 
		COMMAND ${CMAKE_COMMAND} -E copy ${SRC} ${DST} 
	)
  endforeach(FILE)
endfunction( CopyFiles )