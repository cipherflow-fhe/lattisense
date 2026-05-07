set(CXX_SDK_SRCS cxx_fhe_task.cpp cxx_fhe_task_cpu.cpp)
if(LATTISENSE_ENABLE_GPU)
    list(APPEND CXX_SDK_SRCS cxx_fhe_task_gpu.cpp)
endif()
if(LATTISENSE_ENABLE_FPGA)
    list(APPEND CXX_SDK_SRCS cxx_fhe_task_fpga.cpp cxx_fpga_ops.cpp)
endif()

add_library(cxx_sdk_v2_obj OBJECT ${CXX_SDK_SRCS})
target_include_directories(cxx_sdk_v2_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/
)
if(LATTISENSE_ENABLE_GPU)
    target_compile_definitions(cxx_sdk_v2_obj PRIVATE LATTISENSE_ENABLE_GPU)
endif()

add_library(cxx_sdk_v2 SHARED $<TARGET_OBJECTS:cxx_sdk_v2_obj>)

target_include_directories(cxx_sdk_v2 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/
)

set(LINK_LIBS fhe_ops_lib abi cpu_mega_ag_runner dl m)

if(LATTISENSE_ENABLE_FPGA)
    list(APPEND LINK_LIBS fpga_mega_ag_runner)
endif()

if(LATTISENSE_ENABLE_GPU)
    list(APPEND LINK_LIBS gpu_mega_ag_runner CUDA::cudart)
endif()

target_link_libraries(cxx_sdk_v2 PUBLIC ${LINK_LIBS})
target_link_libraries(cxx_sdk_v2 PRIVATE stdc++)

# Set RPATH so installed library can find dependencies
set_target_properties(cxx_sdk_v2 PROPERTIES
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH_USE_LINK_PATH FALSE
)

file(GLOB_RECURSE DAT_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/../backends/lattisense-fpga/lattisense-fpga-runtime/resource/fpga_tasks/ ${CMAKE_CURRENT_SOURCE_DIR}/../backends/lattisense-fpga/lattisense-fpga-runtime/resource/fpga_tasks/**/*.dat ${CMAKE_CURRENT_SOURCE_DIR}/../backends/lattisense-fpga/lattisense-fpga-runtime/resource/fpga_tasks/*.dat)
foreach(DAT_FILE ${DAT_FILES})
    get_filename_component(DAT_FILE_DIR ${DAT_FILE} DIRECTORY)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/backends/lattisense-fpga/lattisense-fpga-runtime/resource/fpga_tasks/${DAT_FILE_DIR})
    add_custom_command(TARGET cxx_sdk_v2 PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/../backends/lattisense-fpga/lattisense-fpga-runtime/resource/fpga_tasks/${DAT_FILE} ${CMAKE_BINARY_DIR}/backends/lattisense-fpga/lattisense-fpga-runtime/resource/fpga_tasks/${DAT_FILE})
endforeach()
