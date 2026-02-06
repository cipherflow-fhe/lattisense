# Define test base paths
# Users can override with -DCPU_TEST_BASE_DIR and -DGPU_TEST_BASE_DIR
if(NOT DEFINED CPU_TEST_BASE_DIR)
    set(CPU_TEST_BASE_DIR "${CMAKE_SOURCE_DIR}/unittests/test_data/cpu" CACHE PATH "Path to CPU test data")
endif()
if(NOT DEFINED GPU_TEST_BASE_DIR)
    set(GPU_TEST_BASE_DIR "${CMAKE_SOURCE_DIR}/unittests/test_data/gpu" CACHE PATH "Path to GPU test data")
endif()

message(STATUS "CPU Test Base Directory: ${CPU_TEST_BASE_DIR}")
message(STATUS "GPU Test Base Directory: ${GPU_TEST_BASE_DIR}")

# Generate test_config.hpp for C++ tests
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/test_config.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/test_config.hpp"
    @ONLY
)

# Generate test_config.py for Python tests
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/test_config.py.in"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_config.py"
    @ONLY
)

add_executable(test_lattigo test_lattigo.cpp utils.cpp)
include_directories(test_lattigo ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_lattigo cxx_sdk_v2)

add_executable(test_cpu_bfv test_cpu_bfv.cpp)
include_directories(test_cpu_sim_bfv ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_cpu_bfv cxx_sdk_v2)

if(LATTISENSE_ENABLE_GPU)
    add_executable(test_gpu_bfv test_gpu_bfv.cpp)
    include_directories(test_gpu_bfv ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_gpu_bfv cxx_sdk_v2)
    target_compile_definitions(test_gpu_bfv PRIVATE LATTISENSE_ENABLE_GPU)

    add_executable(test_gpu_ckks test_gpu_ckks.cpp)
    include_directories(test_gpu_ckks ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_gpu_ckks cxx_sdk_v2)
    target_compile_definitions(test_gpu_ckks PRIVATE LATTISENSE_ENABLE_GPU)
endif()

add_executable(test_cpu_ckks test_cpu_ckks.cpp)
include_directories(test_cpu_sim_ckks ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_cpu_ckks cxx_sdk_v2)

add_executable(test_mp_lattigo test_mp_lattigo.cpp utils.cpp)
include_directories(test_mp_lattigo ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_mp_lattigo cxx_sdk_v2)

if(OPENMP_FOUND)
    message(STATUS "Found OpenMP version: ${OpenMP_VERSION}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

set(TEST_LAYER_PATH "${CMAKE_SOURCE_DIR}/test_app/test_layer")
file(GLOB_RECURSE TEST_LAYER_SOURCES ${TEST_LAYER_PATH}/*.cpp)

