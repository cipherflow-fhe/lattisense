# CPU Benchmark
add_executable(benchmark_cpu benchmark_cpu.cpp)
target_link_libraries(benchmark_cpu PRIVATE lattisense)

# Copy Python script to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/benchmark_cpu.py
               ${CMAKE_CURRENT_BINARY_DIR}/benchmark_cpu.py COPYONLY)
