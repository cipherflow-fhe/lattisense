## lattigo 插件
1. `test_fpga`目录下为单元测试例程，运行单元测试例程之前，需要确保fhe-sdk-v2项目已经在`${CMAKE_SOURCE_DIR}/build`目录下编译，并且采用了`cmake -DFHE_C_SDK_BUILD_DLL=ON`选项，否则运行时会找不到依赖的`c_sdk_v2.so`动态库（当前不支持静态链接）。