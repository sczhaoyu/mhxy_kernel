include(MhxyKernelComponent)

set(SOURCES
	main.cpp
	)

set(HEADERS
	
	)

add_executable(test_dll  "${SOURCES}" "${HEADERS}")

 
target_include_directories(test_dll BEFORE PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>)

target_link_libraries(test_dll mhxy_kernel)

install(TARGETS test_dll RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})