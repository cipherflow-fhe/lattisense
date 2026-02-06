add_executable(bfv_poly_7_cpu bfv_poly_7_cpu.cpp)
target_link_libraries(bfv_poly_7_cpu PRIVATE lattisense)

set_target_properties(bfv_poly_7_cpu PROPERTIES
    INSTALL_RPATH "$ORIGIN/../../../lib"
    BUILD_WITH_INSTALL_RPATH OFF
)

# Copy Python script to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bfv_poly_7_cpu.py
               ${CMAKE_CURRENT_BINARY_DIR}/bfv_poly_7_cpu.py COPYONLY)
