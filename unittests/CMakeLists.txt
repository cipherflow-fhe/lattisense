# Define test base path
# Users can override with -DTEST_BASE_DIR
if(NOT DEFINED TEST_BASE_DIR)
    set(TEST_BASE_DIR "${CMAKE_SOURCE_DIR}/unittests/test_data" CACHE PATH "Path to test data base directory")
endif()

message(STATUS "Test Base Directory: ${TEST_BASE_DIR}")
message(STATUS "  CPU  tests: ${TEST_BASE_DIR}/cpu_tests")
message(STATUS "  GPU  tests: ${TEST_BASE_DIR}/gpu_tests")

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

add_executable(test_bfv test_bfv.cpp utils.cpp ../fhe_ops_lib/unittests/test_utils.cpp)
include_directories(test_bfv ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_bfv cxx_sdk_v2)
if(LATTISENSE_ENABLE_GPU)
    target_compile_definitions(test_bfv PRIVATE LATTISENSE_ENABLE_GPU)
endif()

add_executable(test_ckks test_ckks.cpp utils.cpp ../fhe_ops_lib/unittests/test_utils.cpp)
include_directories(test_ckks ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_ckks cxx_sdk_v2)
if(LATTISENSE_ENABLE_GPU)
    target_compile_definitions(test_ckks PRIVATE LATTISENSE_ENABLE_GPU)
endif()

add_executable(test_fhe_task_param test_fhe_task_param.cpp utils.cpp ../fhe_ops_lib/unittests/test_utils.cpp)
include_directories(test_fhe_task_param ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_fhe_task_param cxx_sdk_v2)

add_executable(test_task_cancellation test_task_cancellation.cpp utils.cpp ../fhe_ops_lib/unittests/test_utils.cpp)
include_directories(test_task_cancellation ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_task_cancellation cxx_sdk_v2)
if(LATTISENSE_ENABLE_GPU)
    target_compile_definitions(test_task_cancellation PRIVATE LATTISENSE_ENABLE_GPU)
endif()

if(OPENMP_FOUND)
    message(STATUS "Found OpenMP version: ${OpenMP_VERSION}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

set(TEST_LAYER_PATH "${CMAKE_SOURCE_DIR}/test_app/test_layer")
file(GLOB_RECURSE TEST_LAYER_SOURCES ${TEST_LAYER_PATH}/*.cpp)

