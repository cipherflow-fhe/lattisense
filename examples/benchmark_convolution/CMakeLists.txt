# Benchmark Convolution Example

# Common source files
set(CONV_SOURCES
    conv2d_layer.cpp
    conv2d_packed_layer.cpp
)

# CPU version
add_executable(benchmark_convolution_cpu
    benchmark_convolution_cpu.cpp
    ${CONV_SOURCES}
)
target_link_libraries(benchmark_convolution_cpu PRIVATE lattisense)
target_include_directories(benchmark_convolution_cpu PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# GPU version
if(LATTISENSE_ENABLE_GPU)
    add_executable(benchmark_convolution_gpu
        benchmark_convolution_gpu.cpp
        ${CONV_SOURCES}
    )
    target_link_libraries(benchmark_convolution_gpu PRIVATE lattisense)
    target_include_directories(benchmark_convolution_gpu PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# Copy Python script to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/benchmark_convolution.py
               ${CMAKE_CURRENT_BINARY_DIR}/benchmark_convolution.py COPYONLY)
