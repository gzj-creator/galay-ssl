# Build switches for galay-ssl.

option(BUILD_TESTS "Build test executables" ON)
option(BUILD_BENCHMARKS "Build benchmark executables" ON)
option(BUILD_EXAMPLES "Build example executables" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(ENABLE_LOG "Enable logging with spdlog" ON)
option(DISABLE_IOURING "Disable io_uring and use epoll on Linux" OFF)
option(ENABLE_LTO "Enable IPO/LTO for Release builds" ON)
option(BUILD_MODULE_EXAMPLES "Build C++23 module(import/export) examples" ON)
