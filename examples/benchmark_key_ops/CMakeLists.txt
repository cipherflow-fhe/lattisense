# Key operator benchmark example
add_executable(benchmark_key_ops benchmark_key_ops.cpp)
target_link_libraries(benchmark_key_ops PRIVATE lattisense)

if(LATTISENSE_ENABLE_GPU)
    target_compile_definitions(benchmark_key_ops PRIVATE LATTISENSE_ENABLE_GPU)
endif()

# Configure Python task generator with the source tree path so the copied
# build-directory script can import frontend.custom_task.
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/benchmark_key_ops.py
               ${CMAKE_CURRENT_BINARY_DIR}/benchmark_key_ops.py @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sort_benchmark_key_ops_csv.py
               ${CMAKE_CURRENT_BINARY_DIR}/sort_benchmark_key_ops_csv.py COPYONLY)
