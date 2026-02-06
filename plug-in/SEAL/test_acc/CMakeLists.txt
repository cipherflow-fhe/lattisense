if(LATTISENSE_ENABLE_GPU)
    add_executable(test_seal_bfv_gpu_acc test_bfv_gpu.cpp utils.cpp)
    target_include_directories(test_seal_bfv_gpu_acc PUBLIC ../acc)
    target_link_libraries(test_seal_bfv_gpu_acc PUBLIC seal_acc)

    add_executable(test_seal_ckks_gpu_acc test_ckks_gpu.cpp utils.cpp)
    target_include_directories(test_seal_ckks_gpu_acc PUBLIC ../acc)
    target_link_libraries(test_seal_ckks_gpu_acc PUBLIC seal_acc)
endif()
