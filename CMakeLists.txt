cmake_minimum_required(VERSION 3.16)

project(galay-ssl VERSION 1.0.0 LANGUAGES CXX)

if(POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW)
endif()

# 设置C++标准
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 构建选项
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_BENCHMARKS "Build benchmark executables" ON)
option(BUILD_EXAMPLES "Build example executables" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(ENABLE_LOG "Enable logging with spdlog" ON)
option(DISABLE_IOURING "Disable io_uring and use epoll on Linux" OFF)
option(ENABLE_LTO "Enable IPO/LTO for Release builds" ON)

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

# 设置安装目录
set(CMAKE_INSTALL_PREFIX /usr/local)

# 查找OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL development libraries.")
endif()
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# 使用系统安装的 galay-kernel
set(GALAY_KERNEL_INCLUDE_DIR "/usr/local/include")
set(GALAY_KERNEL_LIB_DIR "/usr/local/lib")

# 添加 galay-kernel 头文件路径
include_directories(BEFORE ${GALAY_KERNEL_INCLUDE_DIR})

# 创建导入的静态库目标
add_library(galay-kernel-dev STATIC IMPORTED)
set_target_properties(galay-kernel-dev PROPERTIES
    IMPORTED_LOCATION "${GALAY_KERNEL_LIB_DIR}/libgalay-kernel.a"
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

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
