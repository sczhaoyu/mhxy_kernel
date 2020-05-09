foreach( mylibfolder
        Kernel
        TestDLL
    )

    add_subdirectory(${mylibfolder})

endforeach( mylibfolder )

get_property(coreSources GLOBAL PROPERTY CORE_SOURCES)
 

add_library(mhxy_kernel SHARED  ${coreSources} ${localExpatSources})



install(TARGETS mhxy_kernel RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

