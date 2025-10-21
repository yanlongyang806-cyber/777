cmake_minimum_required(VERSION 3.15)
project(veh_patch_project LANGUAGES CXX)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Release)

add_library(veh_patch SHARED src/veh_patch_basic.cpp)
add_library(veh_patch_smart SHARED src/veh_patch_smart.cpp)
