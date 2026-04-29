cmake_minimum_required(VERSION 3.18)
project(heap_oracle_hook C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(heap_oracle_hook SHARED
	src/hook.c
	src/ringbuf.c
)

target_include_directories(heap_oracle_hook PRIVATE include)

if(APPLE)
	target_sources(heap_oracle_hook PRIVATE src/platform/macos.c)
	find_library(FOUNDATION_FRAMEWORK Foundation)
	if(FOUNDATION_FRAMEWORK)
		target_link_libraries(heap_oracle_hook PRIVATE ${FOUNDATION_FRAMEWORK})
	endif()
elseif(WIN32)
	target_sources(heap_oracle_hook PRIVATE src/platform/windows.c)
	target_link_libraries(heap_oracle_hook PRIVATE dbghelp)
else()
	target_sources(heap_oracle_hook PRIVATE src/platform/linux.c)
	target_link_libraries(heap_oracle_hook PRIVATE dl rt)
endif()

set_target_properties(heap_oracle_hook PROPERTIES
	OUTPUT_NAME heap_oracle_hook
)

install(TARGETS heap_oracle_hook DESTINATION lib)