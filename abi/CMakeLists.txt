set(ABI_SRCS c_structs.c)

add_library(abi SHARED ${ABI_SRCS})
target_include_directories(abi PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fhe_ops_lib/lattigo/go_sdk/
)
target_link_libraries(abi PUBLIC ${CMAKE_SOURCE_DIR}/fhe_ops_lib/lattigo/go_sdk/liblattigo.so)

set_target_properties(abi PROPERTIES
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH_USE_LINK_PATH FALSE
)
