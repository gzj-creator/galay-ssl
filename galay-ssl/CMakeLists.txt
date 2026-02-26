# 收集源文件
file(GLOB_RECURSE SOURCES
    "*/*.cc"
)

# 收集头文件
file(GLOB_RECURSE HEADERS
    "*/*.h"
    "*/*.hpp"
)

# 创建库目标
add_library(galay-ssl ${SOURCES} ${HEADERS})
target_compile_features(galay-ssl PUBLIC cxx_std_23)

# 设置包含目录
target_include_directories(galay-ssl
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include/galay-ssl>
)

# 查找平台相关库
if(UNIX AND NOT APPLE)
    find_library(URING_LIB uring)
    find_library(AIO_LIB aio)
    if(URING_LIB)
        list(APPEND PLATFORM_LIBS ${URING_LIB})
    endif()
    if(AIO_LIB)
        list(APPEND PLATFORM_LIBS ${AIO_LIB})
    endif()
endif()

# 链接 galay-kernel（使用系统安装的库）
target_link_libraries(galay-ssl PUBLIC
    galay-kernel::galay-kernel
    OpenSSL::SSL OpenSSL::Crypto
    ${PLATFORM_LIBS}
)

# 设置库的编译选项
target_compile_options(galay-ssl PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

# 设置库的属性
set_target_properties(galay-ssl PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME galay-ssl
)

# 安装库文件
install(TARGETS galay-ssl
    EXPORT galay-ssl-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

# 安装头文件（保留目录结构）
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION include/galay-ssl
    FILES_MATCHING
    PATTERN "*.h"
    PATTERN "*.hpp"
    PATTERN "*.cppm"
    PATTERN "*.cc" EXCLUDE
)

# 安装配置文件
include(CMakePackageConfigHelpers)

# 生成版本文件
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/galay-ssl-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# 生成配置文件
configure_package_config_file(
    "${CMAKE_SOURCE_DIR}/galay-ssl-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/galay-ssl-config.cmake"
    INSTALL_DESTINATION lib/cmake/galay-ssl
    PATH_VARS
        CMAKE_INSTALL_PREFIX
)

# 安装配置文件
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/galay-ssl-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/galay-ssl-config-version.cmake"
    DESTINATION lib/cmake/galay-ssl
)

# 安装导出目标
install(EXPORT galay-ssl-targets
    FILE galay-ssl-targets.cmake
    NAMESPACE galay-ssl::
    DESTINATION lib/cmake/galay-ssl
)
