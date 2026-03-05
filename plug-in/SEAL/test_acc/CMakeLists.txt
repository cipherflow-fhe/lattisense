if(NOT DEFINED TEST_BASE_DIR)
    set(TEST_BASE_DIR "${CMAKE_SOURCE_DIR}/unittests/test_data" CACHE PATH "Path to test data base directory")
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/test_config.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/test_config.hpp"
    @ONLY
)

add_executable(test_seal_bfv_fpga_acc test_bfv_fpga.cpp utils.cpp)
target_include_directories(test_seal_bfv_fpga_acc PUBLIC ../acc ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_seal_bfv_fpga_acc PUBLIC seal_acc)

add_executable(test_seal_ckks_fpga_acc test_ckks_fpga.cpp utils.cpp)
target_include_directories(test_seal_ckks_fpga_acc PUBLIC ../acc ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_seal_ckks_fpga_acc PUBLIC seal_acc)

if(LATTISENSE_ENABLE_GPU)
    add_executable(test_seal_bfv_gpu_acc test_bfv_gpu.cpp utils.cpp)
    target_include_directories(test_seal_bfv_gpu_acc PUBLIC ../acc ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_seal_bfv_gpu_acc PUBLIC seal_acc)

    add_executable(test_seal_ckks_gpu_acc test_ckks_gpu.cpp utils.cpp)
    target_include_directories(test_seal_ckks_gpu_acc PUBLIC ../acc ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_seal_ckks_gpu_acc PUBLIC seal_acc)
endif()
