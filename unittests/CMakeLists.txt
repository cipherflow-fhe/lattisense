# Define test base path
# Users can override with -DTEST_BASE_DIR
if(NOT DEFINED TEST_BASE_DIR)
    set(TEST_BASE_DIR "${CMAKE_SOURCE_DIR}/unittests/test_data" CACHE PATH "Path to test data base directory")
endif()

message(STATUS "Test Base Directory: ${TEST_BASE_DIR}")
message(STATUS "  CPU  tests: ${TEST_BASE_DIR}/cpu_tests")
message(STATUS "  GPU  tests: ${TEST_BASE_DIR}/gpu_tests")
message(STATUS "  FPGA tests: ${TEST_BASE_DIR}/fpga_tests/noc_config_16c_3")

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

function(register_lattisense_executable_test target_name)
    add_test(NAME ${target_name} COMMAND ${target_name})
    set_tests_properties(${target_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endfunction()

function(register_lattisense_pytest test_name script_name)
    add_test(
        NAME ${test_name}
        COMMAND ${Python3_EXECUTABLE} -m pytest ${CMAKE_CURRENT_SOURCE_DIR}/${script_name} -v
    )
    set_tests_properties(${test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endfunction()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_executable(test_cpu_bfv test_cpu_bfv.cpp utils.cpp)
include_directories(test_cpu_bfv ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_cpu_bfv cxx_sdk_v2)
register_lattisense_executable_test(test_cpu_bfv)

add_executable(test_fhe_task_param test_fhe_task_param.cpp utils.cpp)
include_directories(test_fhe_task_param ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_fhe_task_param cxx_sdk_v2)
register_lattisense_executable_test(test_fhe_task_param)

add_executable(test_cpu_ckks test_cpu_ckks.cpp utils.cpp)
include_directories(test_cpu_ckks ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_cpu_ckks cxx_sdk_v2)
register_lattisense_executable_test(test_cpu_ckks)

add_executable(test_lattigo test_lattigo.cpp utils.cpp)
include_directories(test_lattigo ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_lattigo cxx_sdk_v2)
register_lattisense_executable_test(test_lattigo)

add_executable(test_mp_lattigo test_mp_lattigo.cpp utils.cpp)
include_directories(test_mp_lattigo ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_mp_lattigo cxx_sdk_v2)
register_lattisense_executable_test(test_mp_lattigo)

register_lattisense_pytest(test_cpu_bfv_py test_cpu_bfv.py)
register_lattisense_pytest(test_cpu_ckks_py test_cpu_ckks.py)

set_tests_properties(test_cpu_bfv PROPERTIES DEPENDS test_cpu_bfv_py)
set_tests_properties(test_fhe_task_param PROPERTIES DEPENDS test_cpu_bfv_py)
set_tests_properties(test_cpu_ckks PROPERTIES DEPENDS test_cpu_ckks_py)

if(LATTISENSE_ENABLE_FPGA)
    add_executable(test_fpga_bfv test_fpga_bfv.cpp utils.cpp)
    include_directories(test_fpga_bfv ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib)
    target_link_libraries(test_fpga_bfv cxx_sdk_v2)
    target_compile_definitions(test_fpga_bfv PRIVATE LATTISENSE_ENABLE_FPGA)
    register_lattisense_executable_test(test_fpga_bfv)
    register_lattisense_pytest(test_fpga_bfv_py test_fpga_bfv.py)
    set_tests_properties(test_fpga_bfv PROPERTIES DEPENDS test_fpga_bfv_py)

    add_executable(test_fpga_ckks test_fpga_ckks.cpp utils.cpp)
    include_directories(test_fpga_ckks ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib)
    target_link_libraries(test_fpga_ckks cxx_sdk_v2)
    target_compile_definitions(test_fpga_ckks PRIVATE LATTISENSE_ENABLE_FPGA)
    register_lattisense_executable_test(test_fpga_ckks)
    register_lattisense_pytest(test_fpga_ckks_py test_fpga_ckks.py)
    set_tests_properties(test_fpga_ckks PROPERTIES DEPENDS test_fpga_ckks_py)
endif()

if(LATTISENSE_ENABLE_GPU)
    add_executable(test_gpu_bfv test_gpu_bfv.cpp utils.cpp)
    include_directories(test_gpu_bfv ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_gpu_bfv cxx_sdk_v2)
    target_compile_definitions(test_gpu_bfv PRIVATE LATTISENSE_ENABLE_GPU)
    register_lattisense_executable_test(test_gpu_bfv)
    register_lattisense_pytest(test_gpu_bfv_py test_gpu_bfv.py)
    set_tests_properties(test_gpu_bfv PROPERTIES DEPENDS test_gpu_bfv_py)

    add_executable(test_gpu_ckks test_gpu_ckks.cpp utils.cpp)
    include_directories(test_gpu_ckks ${CMAKE_CURRENT_SOURCE_DIR}/../cxx_sdk_v2 ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(test_gpu_ckks cxx_sdk_v2)
    target_compile_definitions(test_gpu_ckks PRIVATE LATTISENSE_ENABLE_GPU)
    register_lattisense_executable_test(test_gpu_ckks)
    register_lattisense_pytest(test_gpu_ckks_py test_gpu_ckks.py)
    set_tests_properties(test_gpu_ckks PROPERTIES DEPENDS test_gpu_ckks_py)
endif()

if(OPENMP_FOUND)
    message(STATUS "Found OpenMP version: ${OpenMP_VERSION}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

set(TEST_LAYER_PATH "${CMAKE_SOURCE_DIR}/test_app/test_layer")
file(GLOB_RECURSE TEST_LAYER_SOURCES ${TEST_LAYER_PATH}/*.cpp)

