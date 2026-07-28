set(ACC_SRC_FILES runner.cpp)
set(ACC_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/abi ${CMAKE_SOURCE_DIR}/mega_ag_runners ${SEAL_DIR})
set(ACC_LINK_LIBS abi seal-4.1)

if(LATTISENSE_ENABLE_FPGA)
    list(APPEND ACC_SRC_FILES fpga_runner.cpp)
    list(APPEND ACC_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/mega_ag_runners/fpga)
    list(APPEND ACC_LINK_LIBS fpga_mega_ag_runner)
endif()

if(LATTISENSE_ENABLE_GPU)
    list(APPEND ACC_SRC_FILES gpu_runner.cpp)
    list(APPEND ACC_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/mega_ag_runners/gpu)
    list(APPEND ACC_LINK_LIBS gpu_mega_ag_runner HEonGPU::heongpu CUDA::cudart)
endif()

add_library(seal_acc ${ACC_SRC_FILES})
target_include_directories(seal_acc PUBLIC ${ACC_INCLUDE_DIRS})
target_link_libraries(seal_acc PUBLIC ${ACC_LINK_LIBS})

if(LATTISENSE_ENABLE_GPU)
    set_target_properties(seal_acc PROPERTIES CUDA_SEPARABLE_COMPILATION ON)
endif()
