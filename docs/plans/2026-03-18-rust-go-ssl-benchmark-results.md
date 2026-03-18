# Rust/Go SSL Benchmark Results

## Scope

本页记录 2026-03-18 在本地 macOS 环境下完成的受控对比结果，以及远端 Linux 正式 benchmark 当前的阻塞状态。

当前已完成的是“服务端口径”对比：

- `galay-ssl`
- Rust `tokio-rustls`
- Go `crypto/tls`

固定项：

- 同一客户端：`build-crosslang-contract/bin/B1-SslBenchClient`
- 同一证书：`certs/server.crt` / `certs/server.key`
- 同一 echo 语义：按读取字节数原样写回
- 同一 TLS 口径：`TLS 1.3 only`
- 同一客户端参数：连接数 / 请求数 / payload / 线程数完全一致

## Local Environment

- OS: macOS 15.7.3
- CPU: Apple M4
- Logical CPUs: 10
- C++ compiler: Apple clang 17.0.0
- OpenSSL: 3.5.0
- Rust: `rustc 1.91.1`
- Go: `go1.24.3 darwin/arm64`
- Repo HEAD: `0bb2d93aac3c4b551737ceb77a5c7c4e6c3d0280`

## Contract Checks

在采样前补了最小合同验证：

- `galay-ssl` / Rust / Go 三个服务端都拒绝 `TLS 1.2`
- 三个服务端都能通过 `B1-SslBenchClient` 的 `1x1` smoke

当前还**没有**自动化验证 “no-resumption” 的端到端检查；这一点仍然需要后续补齐。

## Commands

### Streaming

- `connections = 64`
- `requests_per_conn = 500`
- `payload_bytes = 256`
- `threads = 4`

### Handshake-Heavy

- `connections = 128`
- `requests_per_conn = 1`
- `payload_bytes = 47`
- `threads = 4`

方法：

- 每个实现每个场景先跑 `1` 次 warmup
- 再跑 `5` 次 formal runs
- 每轮使用独立端口，避免本地快速重启服务端带来的 `bind` 干扰
- 结果按 formal runs 取中位数

原始数据：

- `/tmp/galay-ssl-local-crosslang-20260318-r2/raw.csv`
- `/tmp/galay-ssl-handshake-workers-20260318/raw.csv`

## Results

### Streaming Median

| Implementation | QPS | Throughput MB/s | Median Errors |
|---|---:|---:|---:|
| `galay-ssl` | `160000` | `78.125` | `0` |
| Rust `tokio-rustls` | `165803` | `80.9585` | `0` |
| Go `crypto/tls` | `173913` | `84.9185` | `0` |

相对 `galay-ssl`：

- Rust: `+3.63%`
- Go: `+8.70%`

### Handshake-Heavy Median

| Implementation | QPS | Throughput MB/s | Median Errors |
|---|---:|---:|---:|
| `galay-ssl` | `1600` | `0.143433` | `0` |
| Rust `tokio-rustls` | `2560` | `0.229492` | `0` |
| Go `crypto/tls` | `3121.95` | `0.279869` | `0` |

相对 `galay-ssl`：

- Rust: `+60.00%`
- Go: `+95.12%`

## Interpretation

在这组本地 macOS 数据里：

- `streaming` 长连接场景三者都很接近，但 Rust 和 Go 略快于 `galay-ssl`
- `handshake-heavy` 短连接场景差距更明显，Rust 和 Go 明显领先于 `galay-ssl`

这说明当前 `galay-ssl` 的 steady-state 吞吐并不差，但在握手主导场景下还有可挖空间。

## Multi-Worker Validation (Local macOS)

为验证 “`handshake-heavy` 偏低是否主要由 benchmark 服务端单 scheduler / 单线程模型导致”，本地又补了一轮只针对 `galay-ssl` 的 `worker_count` 验证。

当前 `B1-SslBenchServer` 已支持：

- `./build/bin/B1-SslBenchServer <port> <cert> <key> [backlog] [worker_count]`
- 当 `worker_count > 1` 时，服务端会启用 `SO_REUSEPORT + 多 scheduler + 多 listener`

最小行为验证已经通过：

- `worker_count=2` 时，同一进程下监听 socket 数从 `1` 变成 `2`
- `1x1` smoke 仍然通过

本地 `handshake-heavy` 参数保持不变：

- `connections = 128`
- `requests_per_conn = 1`
- `payload_bytes = 47`
- `threads = 4`
- 每个 `worker_count` 运行 `5` 次，取中位数

结果：

| galay-ssl workers | Median QPS | Relative to 1 worker |
|---|---:|---:|
| `1` | `1422.22` | baseline |
| `2` | `1391.30` | `-2.17%` |
| `4` | `1406.59` | `-1.10%` |

额外线程采样显示：

- `worker_count=4` 时进程内确实存在 `4` 个 scheduler 线程
- 但在本地 macOS `kqueue` 压测期间，采样窗口内基本只有 `1` 个 worker 线程持续占用 CPU

这说明至少在当前本地 macOS 环境下，单纯把 `B1-SslBenchServer` 改成 `reuseport + 多 worker`，并没有把握手压测流量有效摊到多个 worker 上，因此没有消除 `handshake-heavy` 差距。

当前更保守的解释应当是：

- 并发模型差异确实是影响因素之一
- 但它不是当前 `galay-ssl` 在短连接握手场景下的唯一瓶颈
- 本地 `kqueue` 上的 `reuseport` 分流行为也可能让这轮验证低估多 worker 的收益

## Linux Safe Run

远端 Linux 结果已经补齐了一轮“安全采样版”验证。

环境：

- Host: `140.143.142.251`
- OS: Ubuntu 24.04
- CPU: `4 vCPU`, `Intel(R) Xeon(R) Platinum 8255C CPU @ 2.50GHz`
- Backend: `epoll`
- Rust toolchain on host: `cargo 1.75.0`
- Go toolchain on host: `go1.22.2 linux/amd64`

本轮使用的是保守口径，目标是先证明 runner 与 Linux `epoll` 实测链路跑通，而且不会再把远端 CPU 打满：

- `server-cpus = 0`
- `client-cpus = 1`
- `threads = 1`
- `build-jobs = 1`
- `streaming = 16 connections x 200 requests x 256B`
- `handshake = 32 connections x 1 request x 47B`
- `warmup-runs = 1`
- `formal-runs = 2`
- `galay-ssl-workers = 1`

原始结果目录：

- `.crosslang-bench-results/remote-20260318-manual-safe/summary.csv`
- `.crosslang-bench-results/remote-20260318-manual-safe/raw-results.csv`

结果：

| Scenario | Implementation | Median QPS | Throughput MB/s | Median Combined CPU | Total Errors |
|---|---|---:|---:|---:|---:|
| `streaming` | `galay-ssl` | `35368.85` | `17.27` | `4.15` | `0` |
| `streaming` | Go `crypto/tls` | `24966.60` | `12.1907` | `4.90` | `0` |
| `streaming` | Rust `tokio-rustls` | `20896.00` | `10.2031` | `6.125` | `0` |
| `handshake` | `galay-ssl` | `635.2205` | `0.0569` | `2.45` | `0` |
| `handshake` | Go `crypto/tls` | `351.6910` | `0.0315` | `3.175` | `0` |
| `handshake` | Rust `tokio-rustls` | `333.3695` | `0.0299` | `3.90` | `0` |

这轮结果说明：

- 在当前这组 Linux `epoll` 的安全负载下，`galay-ssl` 的 `streaming` 与 `handshake` QPS 都领先于本轮 Rust / Go 对照实现
- 采样阶段 CPU 明显未打满，说明这组数字不是“顶满 CPU 后的极限吞吐”，而是保守绑核/保守阈值下的受控结果

同时，这轮执行也暴露并修复了 runner 的三个兼容问题：

- 远端构建阶段原先没有并行度保护；现已增加 `--build-jobs`
- 旧版 `cargo` 无法读取 `Cargo.lock v4`；现已在 runner 内自动回退处理
- 旧版 Go 工具链会尝试远端拉新 toolchain；现已改为 `go 1.22` 口径并强制 `GOTOOLCHAIN=local`

## Method Limits

- 当前结果是 macOS `kqueue` 环境，不是 Linux `epoll`
- 还没有把 Rust / Go 服务端接入仓库常规测试目标
- 还没有自动化验证 “session resumption 确实关闭”
- 本页结论只代表“当前这台本机 + 当前这组参数 + 当前 HEAD”
