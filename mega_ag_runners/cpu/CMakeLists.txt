set(CPU_MEGA_AG_RUNNER_SRCS
    mega_ag_executors_cpu.cpp
    cpu_wrapper.cpp
)
add_library(cpu_mega_ag_runner_obj OBJECT ${CPU_MEGA_AG_RUNNER_SRCS})
target_include_directories(cpu_mega_ag_runner_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fhe_ops_lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib
)
add_library(cpu_mega_ag_runner SHARED
    $<TARGET_OBJECTS:cpu_mega_ag_runner_obj>
    $<TARGET_OBJECTS:mega_ag_obj>
)
target_link_libraries(cpu_mega_ag_runner PUBLIC fhe_ops_lib)
set_target_properties(cpu_mega_ag_runner PROPERTIES
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH_USE_LINK_PATH FALSE
)
