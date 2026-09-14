add_executable(test_fhe_ops_lib_bfv test_bfv.cpp test_utils.cpp)
target_include_directories(test_fhe_ops_lib_bfv PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/unittests
)
target_link_libraries(test_fhe_ops_lib_bfv PRIVATE fhe_ops_lib)

add_executable(test_fhe_ops_lib_ckks test_ckks.cpp test_utils.cpp)
target_include_directories(test_fhe_ops_lib_ckks PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/unittests
)
target_link_libraries(test_fhe_ops_lib_ckks PRIVATE fhe_ops_lib)
