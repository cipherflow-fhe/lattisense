set(FPGA_MEGA_AG_RUNNER_SRCS
    fpga_wrapper.cpp
)
add_library(fpga_mega_ag_runner_obj OBJECT ${FPGA_MEGA_AG_RUNNER_SRCS})
target_include_directories(fpga_mega_ag_runner_obj PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../cxx_sdk_v2/
    ${CMAKE_CURRENT_SOURCE_DIR}/../../backends/lattisense-fpga/lattisense-fpga-runtime/libbfv2/include/
    ${CMAKE_CURRENT_SOURCE_DIR}/../../backends/lattisense-fpga/lattisense-fpga-runtime/fpga_ops/
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/wolfssl/include
)

add_library(fpga_mega_ag_runner SHARED
    $<TARGET_OBJECTS:fpga_mega_ag_runner_obj>
    $<TARGET_OBJECTS:mega_ag_obj>
)
target_link_libraries(fpga_mega_ag_runner PUBLIC fhe_ops_lib abi fpga_bfv -Wl,--whole-archive fpga_ops -Wl,--no-whole-archive ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/wolfssl/lib/libwolfssl.a dl m)
set_target_properties(fpga_mega_ag_runner PROPERTIES
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH_USE_LINK_PATH FALSE
)

