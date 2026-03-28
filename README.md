# galay-ssl

`galay-ssl` 是一个基于 C++23 协程、OpenSSL Memory BIO 和 `galay-kernel` 调度器的异步 SSL/TLS 库。

## 仓库真相来源

当文档与实现不一致时，本仓库按以下顺序判定真相：

1. 公开头文件与导出目标：`galay-ssl/ssl/*.h`、`galay-ssl/async/*.h`、`galay-ssl/common/*.h*`
2. 真实实现：`galay-ssl/**/*.cc`
3. 可执行示例：`examples/`
4. 测试：`test/`
5. Benchmark：`benchmark/`
6. Markdown 文档

## 核心能力

- `SslContext`：证书、CA、验证模式、TLS 版本、Cipher、ALPN、Session 缓存配置
- `SslEngine`：单连接级 OpenSSL 封装，基于 Memory BIO 解耦 SSL 与网络 IO
- `SslSocket`：与 `galay-kernel` 协程/调度器集成的异步 SSL socket
- 平台后端：macOS 使用 `kqueue`，Linux 使用 `epoll` 或 `io_uring`
- 示例、测试、benchmark 都在仓库内提供独立 target

## 文档导航

建议先看 `docs/README.md`。以下链接全部对应仓库中的真实文件：

| 顺序 | 文档 | 作用 |
|------|------|------|
| 00 | [00-快速开始](docs/00-快速开始.md) | 依赖、构建、安装后消费、最小运行闭环 |
| 01 | [01-架构设计](docs/01-架构设计.md) | 组件分层、Memory BIO 数据流、生命周期 |
| 02 | [02-API参考](docs/02-API参考.md) | 与公开头文件对齐的 API 参考 |
| 03 | [03-使用指南](docs/03-使用指南.md) | 构建选项、脚本覆盖范围、直接运行命令 |
| 04 | [04-示例代码](docs/04-示例代码.md) | 真实示例文件、target 名、运行命令、验证状态 |
| 05 | [05-性能测试](docs/05-性能测试.md) | 真实 benchmark target、命令、指标口径、历史说明 |
| 06 | [06-高级主题](docs/06-高级主题.md) | ALPN、Session、mTLS、Modules 等高级能力现状 |
| 07 | [07-常见问题](docs/07-常见问题.md) | FAQ、已知限制、排错入口 |

补充说明：

- benchmark 运行入口与限制统一收敛到 [docs/05-性能测试.md](docs/05-性能测试.md)
- `test/certs/README.md` 仅作为测试资产说明保留，不属于主文档面

## 构建前提

| 项目 | 要求 | 说明 |
|------|------|------|
| 编译器 | C++23 | 仓库代码使用 `std::expected` 与协程 |
| CMake | `>= 3.16` | 默认源码构建（库 / tests / benchmarks / include 示例） |
| OpenSSL | 开发包可发现 | `find_package(OpenSSL REQUIRED)` |
| `galay-kernel` | 必需 | `find_package(galay-kernel REQUIRED)` |
| `liburing` | Linux 可选 | 缺失时自动回退 `epoll` |
| Modules | CMake `>= 3.28` + 支持模块扫描的生成器/编译器 | 仅影响 `galay-ssl-modules` 与 import 示例 |

## 构建仓库

从仓库根目录运行：

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_LTO=ON
cmake --build build --parallel
```

说明：

- `BUILD_TESTING` 默认 `OFF`；`BUILD_TESTS` 仅作为兼容别名保留，默认也为 `OFF`
- `BUILD_BENCHMARKS`、`BUILD_EXAMPLES` 默认都是 `ON`
- `BUILD_MODULE_EXAMPLES` 默认 `OFF`，这样默认构建在 CMake `>= 3.16` 时不会因为 modules 而硬失败
- 如果你要生成 import 示例，需要显式传 `-DBUILD_MODULE_EXAMPLES=ON`
- 仅有 CMake `>= 3.28` + `Ninja` / `Visual Studio` 还不够；还必须有编译器侧的模块依赖扫描能力
- 当前根工程会在扫描能力缺失时给出 warning 并自动关闭 `BUILD_MODULE_EXAMPLES`
- 已实测：macOS `AppleClang 17` + CMake `4.0.2` + `Ninja` 在缺少扫描能力时不会生成 import 示例
- Linux 上可用 `-DDISABLE_IOURING=ON` 强制回退到 `epoll`

## 安装与消费

安装：

```bash
cmake --install build --prefix "$PWD/.local"
```

安装后使用 CMake 导出 target：

```cmake
find_package(galay-ssl REQUIRED)
add_executable(your_app main.cpp)
target_link_libraries(your_app PRIVATE galay-ssl::galay-ssl)
```

最小 include 示例：

```cpp
#include <galay-ssl/ssl/SslContext.h>
#include <galay-ssl/async/SslSocket.h>

int main() {
    galay::ssl::SslContext ctx(galay::ssl::SslMethod::TLS_Client);
    return ctx.isValid() ? 0 : 1;
}
```

消费链路说明：

- `galay-ssl-config.cmake` 会自动 `find_dependency(OpenSSL REQUIRED)` 与 `find_dependency(galay-kernel REQUIRED)`
- 本次文档修复期间已重新验证 `cmake --install` + `find_package(galay-ssl REQUIRED)` + 上述 include 写法可以真实编译通过
- 已安装包当前只导出 `galay-ssl::galay-ssl`；没有导出 `galay-ssl::galay-ssl-modules`

## 真实示例、测试与 benchmark

下表只列仓库中真实存在的文件与 target：

| 类型 | 源文件 | Target | 当前状态 |
|------|--------|--------|----------|
| include 示例 | `examples/include/E1-ssl_echo_server.cc` | `E1-SslEchoServer-Include` | 可构建，可运行 |
| include 示例 | `examples/include/E2-ssl_client.cc` | `E2-SslClient-Include` | 可构建，可运行 |
| import 示例 | `examples/import/E1-ssl_echo_server.cc` | `E1-SslEchoServer-Import` | 仅在模块工具链满足时生成 |
| import 示例 | `examples/import/E2-ssl_client.cc` | `E2-SslClient-Import` | 仅在模块工具链满足时生成 |
| 测试 | `test/T1-ssl_socket_test.cc` | `T1-SslSocketTest` | 脚本会运行 |
| 测试 | `test/T2-ssl_loopback_smoke.cc` | `T2-SslLoopbackSmoke` | 脚本会运行 |
| 测试 | `test/T3-ssl_single_shot_semantics.cc` | `T3-SslSingleShotSemantics` | 脚本会运行 |
| benchmark | `benchmark/B1-ssl_bench_server.cc` | `B1-SslBenchServer` | 可构建，可运行 |
| benchmark | `benchmark/B1-ssl_bench_client.cc` | `B1-SslBenchClient` | 可构建，可运行 |

## 直接运行命令

以下命令都以仓库根目录为当前目录：

```bash
# include 示例
./build/bin/E1-SslEchoServer-Include 8443 certs/server.crt certs/server.key
./build/bin/E2-SslClient-Include 127.0.0.1 8443
./build/bin/E2-SslClient-Include localhost 8443 certs/ca.crt

# 测试
ctest --test-dir build --output-on-failure
./build/bin/T1-SslSocketTest
./build/bin/T2-SslLoopbackSmoke
./build/bin/T3-SslSingleShotSemantics

# benchmark
./build/bin/B1-SslBenchServer 8443 certs/server.crt certs/server.key
./build/bin/B1-SslBenchClient 127.0.0.1 8443 200 500 47 4
```

## 仓库脚本的真实覆盖范围

脚本行为以 `scripts/` 为准，不再夸大：

- `./scripts/run.sh build`
  - 配置并构建 `build/`
  - 底层使用 `cmake -S/-B` + `cmake --build`，不再写死 `make`
  - 显式打开 `BUILD_TESTING=ON`、`BUILD_BENCHMARKS=ON`
  - `BUILD_EXAMPLES` 依赖默认值，当前默认也是 `ON`
  - 显式传 `-DBUILD_MODULE_EXAMPLES=OFF`，避免旧缓存把 import 示例重新打开
  - 可在命令后追加 CMake 参数，例如 `./scripts/run.sh build -G Ninja`
- `./scripts/run.sh test`
  - 执行 `ctest --test-dir build --output-on-failure`
  - 当前会覆盖 `T1-SslSocketTest` 到 `T9-SslSequenceBaseErrorBridge`
- `./scripts/run.sh bench`
  - 委托 `scripts/S1-Bench.sh`
  - 要求 `build/` 是 `Release + ENABLE_LTO=ON`
  - 运行固定预设，不等于完整性能评估
- `./scripts/check.sh`
  - 重新执行 `ctest --test-dir build --output-on-failure`
  - 检查 `B1-SslBenchServer`、`B1-SslBenchClient` 是否存在
  - 检查证书文件是否复制到 `build/bin/certs`
  - 不会执行真实吞吐/QPS benchmark

## C++23 Modules 现状

仓库包含模块接口文件：

- `galay-ssl/module/galay.ssl.cppm`
- `galay-ssl/module/ModulePrelude.hpp`

真实行为：

- 根工程只在 `BUILD_MODULE_EXAMPLES=ON`、CMake `>= 3.28`、生成器支持模块且编译器侧模块依赖扫描可用时创建 `galay-ssl-modules`
- import 示例 target 依赖该 target
- 已安装包不会导出 `galay-ssl-modules`
- 因此安装后消费的稳定做法仍是头文件方式 `galay-ssl::galay-ssl`

## 已知限制

- 仓库公开头已经提供 ALPN、Session 复用、CA 路径、TLS 版本与 Cipher 配置 API，其中 ALPN / Session 复用 / TLS 版本 / Cipher / CA 路径已有真实测试 target
- `useDefaultCA()` 仍受运行环境默认信任库影响，仓库没有独立的跨平台 smoke target
- mTLS 仍没有独立的端到端 `examples/` 或 `test/` target
- `test/certs/` 内含客户端证书资产，但仓库内没有现成 mTLS 示例 target 使用它们
- `benchmark` 页如果没有附带新命令输出，则应视为历史或方法说明，而不是“当前最新性能结论”

## 许可证

MIT License
