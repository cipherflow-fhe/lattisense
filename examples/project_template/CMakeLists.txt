cmake_minimum_required(VERSION 3.13)
project(my_fhe_app)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

find_package(LattiSense REQUIRED)

add_executable(my_fhe_app main.cpp)
target_link_libraries(my_fhe_app PRIVATE LattiSense::lattisense)
