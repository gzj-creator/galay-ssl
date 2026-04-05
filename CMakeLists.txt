cmake_minimum_required(VERSION 3.16)

project(galay-ssl VERSION 1.2.1 LANGUAGES CXX)

if(POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW)
endif()

# 设置C++标准
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep imported package headers ahead of stale default system installs.
set(CMAKE_FIND_PACKAGE_PREFER_CONFIG ON)
set(CMAKE_NO_SYSTEM_FROM_IMPORTED ON)

# Prefer sibling galay-kernel package prefixes when available.
get_filename_component(GALAY_SSL_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
set(GALAY_SSL_SIBLING_KERNEL_PREFIX_CANDIDATES
    "${GALAY_SSL_REPO_ROOT}/../galay-kernel/install-local"
    "${GALAY_SSL_REPO_ROOT}/../galay-kernel/_install-smoke-344"
    "${GALAY_SSL_REPO_ROOT}/../galay-kernel/_install-smoke"
)

foreach(_galay_ssl_prefix IN LISTS GALAY_SSL_SIBLING_KERNEL_PREFIX_CANDIDATES)
    if(EXISTS "${_galay_ssl_prefix}/lib/cmake/galay-kernel/galay-kernel-config.cmake")
        list(PREPEND CMAKE_PREFIX_PATH "${_galay_ssl_prefix}")
        if(NOT DEFINED galay-kernel_DIR OR galay-kernel_DIR STREQUAL "")
            set(galay-kernel_DIR
                "${_galay_ssl_prefix}/lib/cmake/galay-kernel"
                CACHE PATH "Preferred sibling galay-kernel package directory" FORCE)
        endif()
        break()
    endif()
endforeach()
list(REMOVE_DUPLICATES CMAKE_PREFIX_PATH)

# 构建选项
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/option.cmake)

if(DEFINED BUILD_TESTS AND NOT DEFINED BUILD_TESTING)
    set(BUILD_TESTING ${BUILD_TESTS} CACHE BOOL "Build the testing tree." FORCE)
elseif(NOT DEFINED BUILD_TESTING)
    set(BUILD_TESTING OFF CACHE BOOL "Build the testing tree." FORCE)
endif()

include(CTest)

# C++23 命名模块支持（参考 galay-rpc 规则）
set(GALAY_SSL_MODULES_SUPPORTED FALSE)
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.28)
    set(GALAY_SSL_MODULES_SUPPORTED TRUE)
endif()

if(BUILD_MODULE_EXAMPLES AND NOT GALAY_SSL_MODULES_SUPPORTED)
    message(WARNING "BUILD_MODULE_EXAMPLES requires CMake >= 3.28; disabling BUILD_MODULE_EXAMPLES.")
    set(BUILD_MODULE_EXAMPLES OFF)
endif()

set(GALAY_SSL_MODULES_GENERATOR_SUPPORTED FALSE)
if(CMAKE_GENERATOR MATCHES "Ninja" OR CMAKE_GENERATOR MATCHES "Visual Studio")
    set(GALAY_SSL_MODULES_GENERATOR_SUPPORTED TRUE)
endif()

if(BUILD_MODULE_EXAMPLES AND NOT GALAY_SSL_MODULES_GENERATOR_SUPPORTED)
    message(WARNING "Generator '${CMAKE_GENERATOR}' does not support C++ modules; disabling BUILD_MODULE_EXAMPLES.")
    set(BUILD_MODULE_EXAMPLES OFF)
endif()

set(GALAY_SSL_MODULES_COMPILER_SUPPORTED TRUE)
if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    set(GALAY_SSL_MODULES_COMPILER_SUPPORTED FALSE)
endif()

if(BUILD_MODULE_EXAMPLES AND NOT GALAY_SSL_MODULES_COMPILER_SUPPORTED)
    message(WARNING "Compiler '${CMAKE_CXX_COMPILER_ID}' does not support C++ module dependency scanning in CMake; disabling BUILD_MODULE_EXAMPLES.")
    set(BUILD_MODULE_EXAMPLES OFF)
endif()

# 设置构建类型
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# 编译选项
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

if(ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT GALAY_SSL_IPO_SUPPORTED OUTPUT GALAY_SSL_IPO_OUTPUT)
    if(GALAY_SSL_IPO_SUPPORTED)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
        message(STATUS "LTO enabled for Release/RelWithDebInfo builds")
    else()
        message(WARNING "ENABLE_LTO=ON but IPO is not supported: ${GALAY_SSL_IPO_OUTPUT}")
    endif()
endif()

# 检测平台并设置调度器宏
if(APPLE)
    add_compile_definitions(USE_KQUEUE)
elseif(UNIX AND NOT APPLE)
    if(DISABLE_IOURING)
        message(STATUS "io_uring disabled, using epoll")
        add_compile_definitions(USE_EPOLL)
    else()
        find_library(URING_LIB uring)
        if(URING_LIB)
            message(STATUS "Found liburing: ${URING_LIB}, using io_uring")
            add_compile_definitions(USE_IOURING)
        else()
            message(STATUS "liburing not found, falling back to epoll")
            add_compile_definitions(USE_EPOLL)
        endif()
    endif()
endif()

# 设置输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 查找OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL development libraries.")
endif()
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# 查找 galay-kernel（支持动态库和静态库）
find_package(galay-kernel 3.4.4 REQUIRED CONFIG)
if(NOT galay-kernel_FOUND)
    message(FATAL_ERROR "galay-kernel not found. Please install galay-kernel first.")
endif()
message(STATUS "Found galay-kernel")

# 包含子目录
add_subdirectory(galay-ssl)

if(BUILD_MODULE_EXAMPLES
   AND GALAY_SSL_MODULES_SUPPORTED
   AND GALAY_SSL_MODULES_GENERATOR_SUPPORTED
   AND GALAY_SSL_MODULES_COMPILER_SUPPORTED)
    add_library(galay-ssl-modules STATIC)
    target_link_libraries(galay-ssl-modules PUBLIC galay-ssl)
    target_sources(galay-ssl-modules
        PUBLIC
            FILE_SET CXX_MODULES
            FILES
                "${CMAKE_CURRENT_SOURCE_DIR}/galay-ssl/module/galay.ssl.cppm"
    )
endif()

if(BUILD_TESTING)
    add_subdirectory(test)
endif()

if(BUILD_BENCHMARKS)
    add_subdirectory(benchmark)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
