# Examples - built as part of SDK (LATTISENSE_BUILD_EXAMPLES=ON)
# These examples demonstrate SDK usage and are meant for learning purposes.
# For standalone project development, see the project_template/ directory.

cmake_minimum_required(VERSION 3.13)

add_subdirectory(bfv_mult_cpu)
add_subdirectory(bfv_poly_7_cpu)
add_subdirectory(ckks_mult_cpu)
add_subdirectory(ckks_mult_serialization_cpu)
add_subdirectory(ckks_euclidean_distance_cpu)
add_subdirectory(ckks_logistic_regression_cpu)
add_subdirectory(benchmark_cpu)
add_subdirectory(benchmark_convolution)
if(LATTISENSE_ENABLE_GPU)
    add_subdirectory(benchmark_gpu)
endif()
