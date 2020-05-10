foreach( mylibfolder
        Kernel
        TestDLL
    )

    add_subdirectory(${mylibfolder})

endforeach( mylibfolder )



set(SPDLOG_HEADERS_DIR "${CMAKE_CURRENT_LIST_DIR}")
file(GLOB SPDLOG_TOP_HEADERS "${SPDLOG_HEADERS_DIR}/spdlog/*.h")
file(GLOB SPDLOG_DETAILS_HEADERS "${SPDLOG_HEADERS_DIR}/spdlog/details/*.h")
file(GLOB SPDLOG_SINKS_HEADERS "${SPDLOG_HEADERS_DIR}/spdlog/sinks/*.h")
file(GLOB SPDLOG_FMT_HEADERS "${SPDLOG_HEADERS_DIR}/spdlog/fmt/*.h")
file(GLOB SPDLOG_FMT_BUNDELED_HEADERS "${SPDLOG_HEADERS_DIR}/spdlog/fmt/bundled/*.h")
set(SPDLOG_ALL_HEADERS ${SPDLOG_TOP_HEADERS} ${SPDLOG_DETAILS_HEADERS} ${SPDLOG_SINKS_HEADERS} ${SPDLOG_FMT_HEADERS}
                       ${SPDLOG_FMT_BUNDELED_HEADERS})
source_group("Header Files\\spdlog" FILES ${SPDLOG_TOP_HEADERS})
source_group("Header Files\\spdlog\\details" FILES ${SPDLOG_DETAILS_HEADERS})
source_group("Header Files\\spdlog\\sinks" FILES ${SPDLOG_SINKS_HEADERS})
source_group("Header Files\\spdlog\\fmt" FILES ${SPDLOG_FMT_HEADERS})
source_group("Header Files\\spdlog\\fmt\\bundled\\" FILES ${SPDLOG_FMT_BUNDELED_HEADERS})


 
get_property(coreSources GLOBAL PROPERTY CORE_SOURCES)
get_property(MG_GROUPS_CORE_SOURCES_C GLOBAL PROPERTY MG_GROUPS_CORE_SOURCES_C)
  string(REPLACE "@" ";" groups ${MG_GROUPS_CORE_SOURCES_C} )
  foreach(g ${groups})
    string(REPLACE "#" ";" g2 ${g})
    list(GET g2 0 name)
    list(REMOVE_AT g2 0)
    source_group("${name}\\Sources" FILES ${g2})
  endforeach()

  get_property(MG_GROUPS_CORE_SOURCES_H GLOBAL PROPERTY MG_GROUPS_CORE_SOURCES_H)
  string(REPLACE "@" ";" groups ${MG_GROUPS_CORE_SOURCES_H} )
  foreach(g ${groups})
    string(REPLACE "#" ";" g2 ${g})
    list(GET g2 0 name)
    list(REMOVE_AT g2 0)
    source_group("${name}\\Headers" FILES ${g2})
  endforeach()

add_library(mhxy_kernel SHARED  ${coreSources}  ${SPDLOG_ALL_HEADERS} )


install(TARGETS mhxy_kernel RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX})

install(DIRECTORY spdlog/ DESTINATION "${CMAKE_INSTALL_PREFIX}/include/spdlog")