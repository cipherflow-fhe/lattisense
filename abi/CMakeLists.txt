set(ABI_SRCS c_structs.c)

add_library(abi_obj OBJECT ${ABI_SRCS})
target_include_directories(abi_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fhe_ops_lib/lattigo/go_sdk/
)
if(TARGET go_libs)
    add_dependencies(abi_obj go_libs)
endif()

add_library(abi SHARED $<TARGET_OBJECTS:abi_obj>)
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
