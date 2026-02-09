cmake_minimum_required(VERSION 3.13)

project(lattisense
    LANGUAGES C CXX ASM
    VERSION 2.0
    DESCRIPTION "LattiSense FHE SDK Version 2.0"
)

set(LATTISENSE_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

#######################
# Dependency Checking #
#######################

# Check C++ compiler version
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "10.0")
        message(FATAL_ERROR
            "GCC version >= 10.0 is required for C++20 support.\n"
            "Current version: ${CMAKE_CXX_COMPILER_VERSION}\n"
            "Please upgrade your compiler or set CMAKE_CXX_COMPILER to a newer version.")
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11.0")
        message(FATAL_ERROR
            "Clang version >= 11.0 is required for C++20 support.\n"
            "Current version: ${CMAKE_CXX_COMPILER_VERSION}\n"
            "Please upgrade your compiler or set CMAKE_CXX_COMPILER to a newer version.")
    endif()
endif()

# Check Go environment
find_program(GO_EXECUTABLE go)
if(NOT GO_EXECUTABLE)
    message(FATAL_ERROR
        "Go compiler not found!\n"
        "Go >= 1.18 is required to build the Lattigo cryptography library.\n"
        "Please install Go from https://golang.org/dl/")
else()
    execute_process(
        COMMAND ${GO_EXECUTABLE} version
        OUTPUT_VARIABLE GO_VERSION_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(STATUS "Found Go: ${GO_VERSION_OUTPUT}")
endif()

# Check Threads
find_package(Threads REQUIRED)

################
# CUDA Support #
################

set(LATTISENSE_CUDA_ARCH "" CACHE STRING
    "CUDA architecture (e.g., 80 for A100, 86 for RTX 30xx, 89 for RTX 40xx, 90 for H100). Required when LATTISENSE_ENABLE_GPU=ON")

find_package(CUDAToolkit QUIET)

if(CUDAToolkit_FOUND)
    message(STATUS "Found CUDA toolkit version ${CUDAToolkit_VERSION}")
    message(STATUS "CUDA_TOOLKIT_ROOT_DIR: ${CUDAToolkit_ROOT}")
else()
    message(STATUS "CUDA toolkit not found, GPU support will be disabled")
endif()

message(STATUS "LATTISENSE_ENABLE_GPU: ${LATTISENSE_ENABLE_GPU}")

if(LATTISENSE_ENABLE_GPU)
    if(NOT CUDAToolkit_FOUND)
        message(FATAL_ERROR
            "CUDA toolkit is required when LATTISENSE_ENABLE_GPU=ON.\n"
            "Please install CUDA toolkit >= 12.0.")
    endif()

    if(NOT LATTISENSE_CUDA_ARCH)
        message(FATAL_ERROR
            "LATTISENSE_CUDA_ARCH is required when LATTISENSE_ENABLE_GPU=ON.\n"
            "\n"
            "Please specify the CUDA architecture for your GPU:\n"
            "  -DLATTISENSE_CUDA_ARCH=80  # A100\n"
            "  -DLATTISENSE_CUDA_ARCH=86  # RTX 30xx\n"
            "  -DLATTISENSE_CUDA_ARCH=89  # RTX 40xx\n"
            "  -DLATTISENSE_CUDA_ARCH=90  # H100\n"
            "\n"
            "See https://developer.nvidia.com/cuda-gpus for your GPU's compute capability.\n"
            "\n"
            "Example:\n"
            "  cmake .. -DLATTISENSE_ENABLE_GPU=ON -DLATTISENSE_CUDA_ARCH=89")
    endif()

    set(CMAKE_CUDA_COMPILER "${CUDAToolkit_BIN_DIR}/nvcc")
    set(CMAKE_CUDA_ARCHITECTURES ${LATTISENSE_CUDA_ARCH})

    enable_language(CUDA)
    cmake_policy(SET CMP0025 NEW)

    project(lattisense
        LANGUAGES C CXX ASM CUDA
        VERSION 2.0
        DESCRIPTION "FHE SDK Version 2.0"
    )

    # Check if HEonGPU is installed
    set(HEONGPU_INSTALL_DIR "${LATTISENSE_ROOT_DIR}/HEonGPU/install")
    set(HEONGPU_BUILD_DIR "${LATTISENSE_ROOT_DIR}/HEonGPU/build")

    if(NOT EXISTS "${HEONGPU_INSTALL_DIR}/lib")
        message(FATAL_ERROR
            "HEonGPU not found at ${HEONGPU_INSTALL_DIR}\n"
            "\n"
            "GPU support requires HEonGPU to be built first. Please run:\n"
            "\n"
            "  cd ${LATTISENSE_ROOT_DIR}/HEonGPU\n"
            "  cmake -S . -B build \\\n"
            "    -DCMAKE_CUDA_ARCHITECTURES=${LATTISENSE_CUDA_ARCH} \\\n"
            "    -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \\\n"
            "    -DCMAKE_INSTALL_PREFIX=\$(pwd)/install\n"
            "  cmake --build build -j\$(nproc)\n"
            "  cmake --install build\n"
            "\n"
            "Then re-run cmake with -DLATTISENSE_ENABLE_GPU=ON -DLATTISENSE_CUDA_ARCH=${LATTISENSE_CUDA_ARCH}")
    endif()

    list(APPEND CMAKE_PREFIX_PATH "${HEONGPU_INSTALL_DIR}")
    # Add CCCL from HEonGPU build directory
    if(EXISTS "${HEONGPU_BUILD_DIR}/_deps/cccl-src/lib/cmake/cccl")
        list(APPEND CMAKE_PREFIX_PATH "${HEONGPU_BUILD_DIR}/_deps/cccl-src/lib/cmake/cccl")
    endif()
    include_directories("${HEONGPU_INSTALL_DIR}/include")
    link_directories("${HEONGPU_INSTALL_DIR}/lib")
    find_package(CUDAToolkit REQUIRED)
    find_package(HEonGPU REQUIRED)
    set(CMAKE_CUDA_FLAGS_DEBUG "${CMAKE_CUDA_FLAGS_DEBUG} -g")
    set(CMAKE_CUDA_FLAGS_RELEASE "${CMAKE_CUDA_FLAGS_RELEASE} -O3")
    message(STATUS "GPU support enabled with HEonGPU (CUDA arch: ${LATTISENSE_CUDA_ARCH})")
endif()

# standard
# set(CMAKE_C_COMPILER "/usr/local/bin/gcc")
# set(CMAKE_CXX_COMPILER "/usr/local/bin/g++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Force linking with the correct standard library
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lstdc++")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -lstdc++")


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CUDA_FLAGS_DEBUG "${CMAKE_CUDA_FLAGS_DEBUG} -g")
set(CMAKE_CUDA_FLAGS_RELEASE "${CMAKE_CUDA_FLAGS_RELEASE} -O3")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
add_compile_definitions(_GLIBCXX_USE_CXX11_ABI=1)
add_definitions(-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D_LARGE_FILE_SOURCE -D_AIO_AIX_SOURCE)

message(STATUS "The CXX compiler : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "The C   compiler : ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "CMAKE_BUILD_TYPE : ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_BINARY_DIR : ${CMAKE_BINARY_DIR}")

# options
option(LATTISENSE_DEV "Enable lattisense development options" OFF)
message(STATUS "LATTISENSE_DEV: ${LATTISENSE_DEV}")
if(LATTISENSE_DEV)
    add_definitions(-DLATTISENSE_DEV)
endif()

option(LATTISENSE_PRINT_PROFILE "Profile mode" OFF)
if(LATTISENSE_PRINT_PROFILE)
    add_definitions(-DPRINT_PROFILE)
endif()

set(LATTISENSE_BUILD_MODE "SHARED" CACHE STRING "SDK build mode: OFF, SHARED")
set_property(CACHE LATTISENSE_BUILD_MODE PROPERTY STRINGS OFF SHARED)
message(STATUS "LATTISENSE_BUILD_MODE: ${LATTISENSE_BUILD_MODE}")

option(LATTISENSE_BUILD_TESTS "Build lattisense tests" OFF)
message(STATUS "LATTISENSE_BUILD_TESTS: ${LATTISENSE_BUILD_TESTS}")

include_directories(${LATTISENSE_ROOT_DIR}/lib ${LATTISENSE_ROOT_DIR}/common)

add_custom_target(go_libs
    COMMAND cd ${LATTISENSE_ROOT_DIR}/fhe_ops_lib/lattigo/go_sdk && bash build.sh
    COMMENT "Building Go dynamic libraries"
)

add_subdirectory(fhe_ops_lib)
add_dependencies(fhe_ops_lib go_libs)
add_subdirectory(cxx_sdk_v2)

add_subdirectory(mega_ag_runners)

if(LATTISENSE_BUILD_TESTS)
    add_subdirectory(unittests)
endif()

if(LATTISENSE_BUILD_MODE STREQUAL "SHARED")
    add_library(lattisense SHARED
        $<TARGET_OBJECTS:cxx_sdk_v2_obj>
        $<TARGET_OBJECTS:fhe_ops_lib_obj>
    )

    target_sources(lattisense PRIVATE
        $<TARGET_OBJECTS:mega_ag_obj>
        $<TARGET_OBJECTS:cpu_mega_ag_runner_obj>
    )
    if(LATTISENSE_ENABLE_GPU)
        target_sources(lattisense PRIVATE
            $<TARGET_OBJECTS:gpu_mega_ag_runner_obj>
        )
    endif()

    target_include_directories(lattisense PUBLIC
        # Build time: source root allows <fhe_ops_lib/xxx.h>, <cxx_sdk_v2/xxx.h>, etc.
        $<BUILD_INTERFACE:${LATTISENSE_ROOT_DIR}>
        $<BUILD_INTERFACE:${LATTISENSE_ROOT_DIR}/lib>
        # Install time: installed include dir allows same include style
        $<INSTALL_INTERFACE:include/lattisense>
    )

    target_link_libraries(lattisense
        PRIVATE
            ${LATTISENSE_ROOT_DIR}/fhe_ops_lib/lattigo/go_sdk/liblattigo.a
        PUBLIC
            dl
            m
            rt
            Threads::Threads
            stdc++
    )

    if(LATTISENSE_ENABLE_GPU)
        target_link_libraries(lattisense PRIVATE HEonGPU::heongpu CUDA::cudart)
        set_target_properties(lattisense PROPERTIES
            CUDA_SEPARABLE_COMPILATION ON
            CUDA_RESOLVE_DEVICE_SYMBOLS ON
        )
    endif()

    set_target_properties(lattisense PROPERTIES
        INSTALL_RPATH "$ORIGIN"
        BUILD_WITH_INSTALL_RPATH OFF
        INSTALL_RPATH_USE_LINK_PATH FALSE
    )

    add_dependencies(lattisense go_libs)
endif()

option(LATTISENSE_BUILD_SEAL_PLUG_IN "Build lattisense plug-in for SEAL" OFF)
message(STATUS "LATTISENSE_BUILD_SEAL_PLUG_IN: ${LATTISENSE_BUILD_SEAL_PLUG_IN}")
if(LATTISENSE_BUILD_SEAL_PLUG_IN)
    if(LATTISENSE_ENABLE_GPU)
        add_subdirectory(plug-in/SEAL)
    else()
        message(WARNING "LATTISENSE_BUILD_SEAL_PLUG_IN requires LATTISENSE_ENABLE_GPU=ON. SEAL plug-in will not be built.")
    endif()
endif()

# install
include(GNUInstallDirs)

# Use standard CMAKE_INSTALL_PREFIX (default: /usr/local on Linux)
# Users can override with: cmake .. -DCMAKE_INSTALL_PREFIX=/custom/path
message(STATUS "CMAKE_INSTALL_PREFIX : ${CMAKE_INSTALL_PREFIX}")

# Define install directories using GNUInstallDirs standards
set(LATTISENSE_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})
set(LATTISENSE_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR}/lattisense)
set(LATTISENSE_INSTALL_DATADIR ${CMAKE_INSTALL_DATADIR}/lattisense)
set(LATTISENSE_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/LattiSense)

# CMake Package Config Support
include(CMakePackageConfigHelpers)

if(LATTISENSE_BUILD_MODE STREQUAL "SHARED")
    # Export target for find_package support
    install(TARGETS lattisense
        EXPORT LattiSenseTargets
        LIBRARY DESTINATION ${LATTISENSE_INSTALL_LIBDIR})

    # Install third-party libraries
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/lib/gsl DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR})
    install(FILES ${LATTISENSE_ROOT_DIR}/lib/nlohmann/json.hpp DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR}/nlohmann)

    # Install header files
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/cxx_sdk_v2/ DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR}/cxx_sdk_v2 FILES_MATCHING
        PATTERN "*.h"
        PATTERN "precision.h" EXCLUDE
        PATTERN "cxx_fhe_task_common.h" EXCLUDE)
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/fhe_ops_lib/ DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR}/fhe_ops_lib FILES_MATCHING
        PATTERN "*.h")
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/mega_ag_runners/ DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR}/mega_ag_runners FILES_MATCHING
        PATTERN "*.h")
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/common/ DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR}/common FILES_MATCHING
        PATTERN "*.h")

    # Install documentation and project template
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/examples/project_template/
        DESTINATION ${LATTISENSE_INSTALL_DATADIR}/project_template
        PATTERN "build" EXCLUDE)
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/doc/ DESTINATION ${LATTISENSE_INSTALL_DATADIR}/doc
        PATTERN "doc_checker.py" EXCLUDE)

    # Install mega_ag_generator (Python frontend for computation graph generation)
    install(CODE "execute_process(COMMAND bash \"-c\" \"mkdir -p ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator/dist ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator/log && cp -r ${LATTISENSE_ROOT_DIR}/frontend ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator && sed -i 's/TRANSLATOR_DEV = True/TRANSLATOR_DEV = False/' ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator/frontend/custom_task.py\")")

    option(LATTISENSE_BUILD_EXAMPLES "Build lattisense examples" OFF)
    message(STATUS "LATTISENSE_BUILD_EXAMPLES: ${LATTISENSE_BUILD_EXAMPLES}")
    if(LATTISENSE_BUILD_EXAMPLES)
        add_subdirectory(examples)
    endif()

    # Generate and install CMake Config Package files

    # Generate version config file
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/LattiSenseConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    # Configure package config file
    configure_package_config_file(
        "${LATTISENSE_ROOT_DIR}/cmake/LattiSenseConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/LattiSenseConfig.cmake"
        INSTALL_DESTINATION ${LATTISENSE_INSTALL_CMAKEDIR}
    )

    # Install CMake config files
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/LattiSenseConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/LattiSenseConfigVersion.cmake"
        DESTINATION ${LATTISENSE_INSTALL_CMAKEDIR}
    )

    # Install exported targets
    install(EXPORT LattiSenseTargets
        FILE LattiSenseTargets.cmake
        NAMESPACE LattiSense::
        DESTINATION ${LATTISENSE_INSTALL_CMAKEDIR}
    )

else()
    option(LATTISENSE_BUILD_EXAMPLES "Build lattisense examples" OFF)
    message(STATUS "LATTISENSE_BUILD_EXAMPLES: ${LATTISENSE_BUILD_EXAMPLES}")
    if(LATTISENSE_BUILD_EXAMPLES)
        add_subdirectory(examples)
    endif()
    install(TARGETS cxx_sdk_v2 LIBRARY DESTINATION ${LATTISENSE_INSTALL_LIBDIR})
    install(TARGETS fhe_ops_lib LIBRARY DESTINATION ${LATTISENSE_INSTALL_LIBDIR})
    install(FILES ${LATTISENSE_ROOT_DIR}/fhe_ops_lib/lattigo/go_sdk/liblattigo.so DESTINATION ${LATTISENSE_INSTALL_LIBDIR})
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/lib/gsl DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR})
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/cxx_sdk_v2/ DESTINATION ${LATTISENSE_INSTALL_INCLUDEDIR}/cxx_sdk_v2 FILES_MATCHING
        PATTERN "*.h"
        PATTERN "precision.h" EXCLUDE
        PATTERN "cxx_fhe_task_common.h" EXCLUDE)
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/doc/ DESTINATION ${LATTISENSE_INSTALL_DATADIR}/doc
        PATTERN "doc_checker.py" EXCLUDE)
    install(CODE "execute_process(COMMAND bash \"-c\" \"mkdir -p ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator/dist ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator/log && cp -r ${LATTISENSE_ROOT_DIR}/frontend ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator && sed -i 's/TRANSLATOR_DEV = True/TRANSLATOR_DEV = False/' ${CMAKE_INSTALL_PREFIX}/${LATTISENSE_INSTALL_DATADIR}/mega_ag_generator/frontend/custom_task.py\")")
    install(DIRECTORY ${LATTISENSE_ROOT_DIR}/examples/project_template/
        DESTINATION ${LATTISENSE_INSTALL_DATADIR}/project_template
        PATTERN "build" EXCLUDE)
endif()
