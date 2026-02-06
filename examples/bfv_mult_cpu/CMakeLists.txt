# BFV Multiplication Example (CPU)
add_executable(bfv_mult_cpu bfv_mult_cpu.cpp)
target_link_libraries(bfv_mult_cpu PRIVATE lattisense)

# Copy Python script to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bfv_mult_cpu.py
               ${CMAKE_CURRENT_BINARY_DIR}/bfv_mult_cpu.py COPYONLY)
