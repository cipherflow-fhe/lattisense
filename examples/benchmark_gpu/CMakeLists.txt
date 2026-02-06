# GPU Benchmark
add_executable(benchmark_gpu benchmark_gpu.cpp)
target_link_libraries(benchmark_gpu PRIVATE lattisense)

# Copy Python script to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/benchmark_gpu.py
               ${CMAKE_CURRENT_BINARY_DIR}/benchmark_gpu.py COPYONLY)
