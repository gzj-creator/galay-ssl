cmake_minimum_required(VERSION 3.16)

project(galay-ssl VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 构建选项
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_BENCHMARKS "Build benchmark executables" ON)
option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(ENABLE_LOG "Enable logging with spdlog" ON)

# 设置构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 编译选项
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# 检测平台并设置调度器宏
if(APPLE)
    add_compile_definitions(USE_KQUEUE)
elseif(UNIX AND NOT APPLE)
    add_compile_definitions(USE_EPOLL)
endif()

# 设置输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 设置安装目录为工作目录下的install
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/install)

# 查找OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL development libraries.")
endif()
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# 使用本地 galay-kernel 源码目录（开发模式）
set(GALAY_KERNEL_SOURCE_DIR "/Users/gongzhijie/Desktop/projects/git/galay-kernel")
set(GALAY_KERNEL_BUILD_DIR "${GALAY_KERNEL_SOURCE_DIR}/build")

# 添加 galay-kernel 头文件路径
include_directories(BEFORE ${GALAY_KERNEL_SOURCE_DIR})

# 创建导入的静态库目标
add_library(galay-kernel-dev STATIC IMPORTED)
set_target_properties(galay-kernel-dev PROPERTIES
    IMPORTED_LOCATION "${GALAY_KERNEL_BUILD_DIR}/lib/libgalay-kernel.a"
)

# 查找spdlog
if(ENABLE_LOG)
    find_package(spdlog QUIET)
    if(NOT spdlog_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            spdlog
            GIT_REPOSITORY https://github.com/gabime/spdlog.git
            GIT_TAG v1.12.0
        )
        FetchContent_MakeAvailable(spdlog)
    endif()
    add_compile_definitions(USE_LOG)
endif()

# 包含子目录
add_subdirectory(galay-ssl)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()

if(BUILD_BENCHMARKS)
    add_subdirectory(benchmark)
endif()
