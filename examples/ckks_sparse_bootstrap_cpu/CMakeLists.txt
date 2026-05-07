add_executable(ckks_sparse_bootstrap_cpu ckks_sparse_bootstrap_cpu.cpp)
target_link_libraries(ckks_sparse_bootstrap_cpu PRIVATE lattisense)

set_target_properties(ckks_sparse_bootstrap_cpu PROPERTIES
    INSTALL_RPATH "$ORIGIN/../../../lib"
    BUILD_WITH_INSTALL_RPATH OFF
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ckks_sparse_bootstrap_cpu.py
               ${CMAKE_CURRENT_BINARY_DIR}/ckks_sparse_bootstrap_cpu.py COPYONLY)
