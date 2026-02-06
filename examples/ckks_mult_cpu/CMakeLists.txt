add_executable(ckks_mult_cpu ckks_mult_cpu.cpp)
target_link_libraries(ckks_mult_cpu PRIVATE lattisense)

set_target_properties(ckks_mult_cpu PROPERTIES
    INSTALL_RPATH "$ORIGIN/../../../lib"
    BUILD_WITH_INSTALL_RPATH OFF
)

# Copy Python script to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ckks_mult_cpu.py
               ${CMAKE_CURRENT_BINARY_DIR}/ckks_mult_cpu.py COPYONLY)
