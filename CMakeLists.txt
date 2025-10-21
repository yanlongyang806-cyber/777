cmake_minimum_required(VERSION 3.15)
project(veh_patch_project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 基础版 DLL
add_library(veh_patch_basic SHARED src/veh_patch_basic.cpp)
set_target_properties(veh_patch_basic PROPERTIES OUTPUT_NAME "veh_patch_basic")

# 智能版 DLL
add_library(veh_patch SHARED src/veh_patch_smart.cpp)
set_target_properties(veh_patch PROPERTIES OUTPUT_NAME "veh_patch")
