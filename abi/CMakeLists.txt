set(ABI_SRCS c_structs.c)

add_library(abi_obj OBJECT ${ABI_SRCS})
target_include_directories(abi_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LATTISENSE_ROOT_DIR}/fhe_ops_lib/lattigo/go_sdk/
)
set_target_properties(abi_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(TARGET go_libs)
    add_dependencies(abi_obj go_libs)
endif()

add_library(abi STATIC $<TARGET_OBJECTS:abi_obj>)
target_include_directories(abi PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LATTISENSE_ROOT_DIR}/fhe_ops_lib/lattigo/go_sdk/
)
target_link_libraries(abi PUBLIC ${LATTISENSE_ROOT_DIR}/fhe_ops_lib/lattigo/go_sdk/liblattigo.a)
if(TARGET go_libs)
    add_dependencies(abi go_libs)
endif()
