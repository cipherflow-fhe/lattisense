if(LATTISENSE_ENABLE_GPU)
    set(FPGA_ACC_SRC_FILES c_struct_import_export.cpp check_sig.cpp runner.cpp)
    set(ACC_SRC_FILES ${FPGA_ACC_SRC_FILES} gpu_runner.cpp)
    add_library(seal_acc ${ACC_SRC_FILES})
    target_include_directories(seal_acc PUBLIC ${CMAKE_SOURCE_DIR}/fhe_ops_lib ${CMAKE_SOURCE_DIR}/mega_ag_runners ${CMAKE_SOURCE_DIR}/mega_ag_runners/gpu ${SEAL_DIR})
    target_link_libraries(seal_acc PUBLIC fhe_ops_lib gpu_mega_ag_runner seal-4.1 HEonGPU::heongpu CUDA::cudart)
    set_target_properties(seal_acc PROPERTIES CUDA_SEPARABLE_COMPILATION ON)
endif()

