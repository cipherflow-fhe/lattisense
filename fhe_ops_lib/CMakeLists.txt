set(FHE_OPS_LIB_SRCS
    fhe_lib_v2.cpp
    utils.cpp
    precision.cpp
    bridge.c
)

if(NOT LATTISENSE_CLIENT_ONLY)
    list(APPEND FHE_OPS_LIB_SRCS structs_v2.c)
endif()

add_library(fhe_ops_lib_obj OBJECT ${FHE_OPS_LIB_SRCS})
target_include_directories(fhe_ops_lib_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lattigo/go_sdk/)
target_compile_definitions(fhe_ops_lib_obj PRIVATE CMAKE_CURRENT_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

add_library(fhe_ops_lib SHARED $<TARGET_OBJECTS:fhe_ops_lib_obj>)
target_include_directories(fhe_ops_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lattigo/go_sdk/)

if(LATTISENSE_CLIENT_ONLY)
    target_link_libraries(fhe_ops_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lattigo/go_sdk/liblattigo.so dl m)
else()
    target_link_libraries(fhe_ops_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lattigo/go_sdk/liblattigo.so dl m)
endif()

set_target_properties(fhe_ops_lib PROPERTIES
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH_USE_LINK_PATH FALSE
)
