add_library(mega_ag_obj OBJECT mega_ag.cpp)
target_include_directories(mega_ag_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fhe_ops_lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)
if(LATTISENSE_ENABLE_GPU)
    target_compile_definitions(mega_ag_obj PRIVATE LATTISENSE_ENABLE_GPU)
endif()

add_subdirectory(cpu)

if(LATTISENSE_ENABLE_GPU)
    add_subdirectory(gpu)
endif()
