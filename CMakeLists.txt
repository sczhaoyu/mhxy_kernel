cmake_minimum_required (VERSION 3.0)


include (CheckFunctionExists)
include (CheckVariableExists)
include (CheckCSourceCompiles)
include (CheckCXXSourceCompiles)
include (CheckIncludeFile)
 



project(mhxy_kernel)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/CMakeModules;${CMAKE_MODULE_PATH}")
if(WIN32)
      set( RT_LIBRARY "winmm" )
      list(APPEND PLATFORM_LIBS "Shlwapi.lib")
      add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
      add_compile_definitions(SPDLOG_COMPILED_LIB)
      
endif(WIN32)

 if(MSVC)
  		set(CMAKE_CXX_FLAGS_RELEASE "/MT")
    	set(CMAKE_CXX_FLAGS_DEBUG "/MTd")
        set(MSVC_FLAGS "-DWIN32 -DNOMINMAX  -D_USE_MATH_DEFINES -D_CRT_SECURE_NO_WARNINGS -D__CRT_NONSTDC_NO_WARNINGS /MP")
 endif(MSVC)


include_directories(  ${CMAKE_SOURCE_DIR}/src)

add_subdirectory(src)


 