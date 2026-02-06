set(CXX_SDK_SRCS cxx_fhe_task.cpp cxx_fhe_task_cpu.cpp)
if(LATTISENSE_ENABLE_GPU)
    list(APPEND CXX_SDK_SRCS cxx_fhe_task_gpu.cpp)
endif()

add_library(cxx_sdk_v2_obj OBJECT ${CXX_SDK_SRCS})
target_include_directories(cxx_sdk_v2_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/
)
if(LATTISENSE_ENABLE_GPU)
    target_compile_definitions(cxx_sdk_v2_obj PRIVATE LATTISENSE_ENABLE_GPU)
endif()

add_library(cxx_sdk_v2 SHARED $<TARGET_OBJECTS:cxx_sdk_v2_obj>)

target_include_directories(cxx_sdk_v2 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/
)

set(LINK_LIBS fhe_ops_lib cpu_mega_ag_runner dl m)

if(LATTISENSE_ENABLE_GPU)
    list(APPEND LINK_LIBS gpu_mega_ag_runner CUDA::cudart)
endif()

target_link_libraries(cxx_sdk_v2 PUBLIC ${LINK_LIBS})
target_link_libraries(cxx_sdk_v2 PRIVATE stdc++)

# Set RPATH so installed library can find dependencies
set_target_properties(cxx_sdk_v2 PROPERTIES
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH_USE_LINK_PATH FALSE
)
