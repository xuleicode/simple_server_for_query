cmake_minimum_required(VERSION 3.10)
project(http_server)

# 查找 libevent 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEVENT REQUIRED libevent)

# 设置编译器标志
set(CMAKE_C_STANDARD 11)

# 设置编译类型（Debug/Release）
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

message(STATUS "构建类型: ${CMAKE_BUILD_TYPE}")

# 根据构建类型设置编译选项
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -DNDEBUG")

# 添加调试符号到所有构建（可选）
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# 创建可执行文件
add_executable(server server.c)

# 链接库
target_link_libraries(server ${LIBEVENT_LIBRARIES})
target_include_directories(server PRIVATE ${LIBEVENT_INCLUDE_DIRS})

# 添加自定义构建类型：RelWithDebInfo（带调试信息的发布版本）
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -O2 -g -DNDEBUG")

# 打印调试信息
message(STATUS "Libevent 包含目录: ${LIBEVENT_INCLUDE_DIRS}")
message(STATUS "Libevent 库目录: ${LIBEVENT_LIBRARY_DIRS}")
message(STATUS "Libevent 库: ${LIBEVENT_LIBRARIES}")