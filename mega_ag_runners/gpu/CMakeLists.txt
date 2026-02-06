add_library(gpu_mega_ag_runner_obj OBJECT
    gpu_wrapper.cu
    mega_ag_executors_gpu.cu
)
target_compile_definitions(gpu_mega_ag_runner_obj PRIVATE LATTISENSE_ENABLE_GPU)
target_include_directories(gpu_mega_ag_runner_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common/
    ${CMAKE_CURRENT_SOURCE_DIR}/../../HEonGPU/install/include/GPUNTT-1.0/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../HEonGPU/install/include/GPUNTT-1.0/ntt_merge
    ${CMAKE_CURRENT_SOURCE_DIR}/../../HEonGPU/install/include/GPUNTT-1.0/ntt_4step
)
target_link_libraries(gpu_mega_ag_runner_obj PUBLIC HEonGPU::heongpu CUDA::cudart)
set_target_properties(gpu_mega_ag_runner_obj PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)

add_library(gpu_mega_ag_runner SHARED
    $<TARGET_OBJECTS:gpu_mega_ag_runner_obj>
    $<TARGET_OBJECTS:mega_ag_obj>
)
target_link_libraries(gpu_mega_ag_runner PUBLIC HEonGPU::heongpu CUDA::cudart)
set_target_properties(gpu_mega_ag_runner PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH_USE_LINK_PATH FALSE
)
