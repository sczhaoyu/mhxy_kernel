
macro(mhxy_kernel_component_common name includePath sourcesList sources headers)
    set(fc${sourcesList} ${name})
    set(fh${sourcesList} ${name})
    foreach(s ${sources})
        set_property(GLOBAL
            APPEND PROPERTY ${sourcesList} "${CMAKE_CURRENT_SOURCE_DIR}/${s}")
        set(fc${sourcesList} "${fc${sourcesList}}#${CMAKE_CURRENT_SOURCE_DIR}/${s}")
    endforeach()

	foreach(h ${headers})
		set_property(GLOBAL
			APPEND PROPERTY PUBLIC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/${h}")
        set(fh${sourcesList} "${fh${sourcesList}}#${CMAKE_CURRENT_SOURCE_DIR}/${h}")

        set_property(GLOBAL
            APPEND PROPERTY ${sourcesList} "${CMAKE_CURRENT_SOURCE_DIR}/${h}")
	endforeach()

    set_property(GLOBAL APPEND PROPERTY MG_GROUPS_${sourcesList}_C "${fc${sourcesList}}@")
    set_property(GLOBAL APPEND PROPERTY MG_GROUPS_${sourcesList}_H "${fh${sourcesList}}@")
    
    install (FILES ${headers}  DESTINATION include/${includePath})
endmacro()

function(mhxy_kernel_component name includePath sources headers)
    mhxy_kernel_component_common(${name} ${includePath} CORE_SOURCES "${sources}" "${headers}")
endfunction()