cmake_minimum_required(VERSION 3.10)
project(VehPatchSmart)

set(CMAKE_CXX_STANDARD 14)

# 设置输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)

# 包含源代码文件
include_directories(${CMAKE_SOURCE_DIR}/src)

# 收集所有 cpp 文件
file(GLOB SOURCES ${CMAKE_SOURCE_DIR}/src/*.cpp)

# 创建共享库（DLL）
add_library(veh_patch_smart SHARED ${SOURCES})

# 设置输出文件名
set_target_properties(veh_patch_smart PROPERTIES OUTPUT_NAME "veh_patch_smart")
