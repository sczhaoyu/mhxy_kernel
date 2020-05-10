include(MhxyKernelComponent)

set(SOURCES
	mhxy_kernel.cpp
	dllmain.cpp
	stdout_sinks.cpp
	async.cpp
	cfg.cpp
	color_sinks.cpp
	file_sinks.cpp
	fmt.cpp
	spdlog.cpp
	)

set(HEADERS
	mhxy_kernel.hpp
	)


mhxy_kernel_component(mhxy_kernel mhxy_kernel "${SOURCES}" "${HEADERS}")



 