include(MhxyKernelComponent)

set(SOURCES
	mhxy_kernel.cpp
	dllmain.cpp
	)

set(HEADERS
	mhxy_kernel.hpp
	)


mhxy_kernel_component(mhxy_kernel mhxy_kernel "${SOURCES}" "${HEADERS}")



 