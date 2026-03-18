# galay-ssl 性能测试

本目录包含 `galay-ssl` 的压测程序，用于评估 SSL/TLS Echo 场景的 QPS、吞吐量和错误率。

## 测试程序

### B1-SslBenchServer

SSL Echo 服务端。

```bash
./build/bin/B1-SslBenchServer <port> <cert_file> <key_file> [backlog] [worker_count]
```

参数：

- `port`：监听端口
- `cert_file`：证书路径
- `key_file`：私钥路径
- `backlog`：可选，默认 `4096`
- `worker_count`：可选，默认 `1`；大于 `1` 时启用 `SO_REUSEPORT + 多 scheduler + 多 listener`

示例：

```bash
./build/bin/B1-SslBenchServer 8443 certs/server.crt certs/server.key
./build/bin/B1-SslBenchServer 8443 certs/server.crt certs/server.key 4096 4
```

### B1-SslBenchClient

SSL 压测客户端。

```bash
./build/bin/B1-SslBenchClient <host> <port> <connections> <requests_per_conn> [payload_bytes] [threads] [connect_retries]
```

参数：

- `host`：服务端地址
- `port`：服务端端口
- `connections`：并发连接数
- `requests_per_conn`：每连接请求数
- `payload_bytes`：可选，单次 payload 大小，默认 `47`
- `threads`：可选，客户端线程数，默认 `1`
- `connect_retries`：可选，连接重试次数，默认 `3`

示例：

```bash
# 小包（默认 47B）
./build/bin/B1-SslBenchClient 127.0.0.1 8443 200 500 47 4

# 大包（64KiB）
./build/bin/B1-SslBenchClient 127.0.0.1 8443 10 200 65536 1
```

## 推荐流程

```bash
# 1) 生成证书（如需要）
bash test/certs/generate_certs.sh

# 2) 启动服务端
./build/bin/B1-SslBenchServer 8443 certs/server.crt certs/server.key 4096 4

# 3) 启动客户端（另一个终端）
./build/bin/B1-SslBenchClient 127.0.0.1 8443 200 500 47 4
```

## Cross-Language Benchmark Contract

用于和 Rust / Go 服务端做受控对比时，当前 C++ benchmark 固定采用以下口径：

- TLS 版本固定为 `TLS 1.3`
- 显式关闭会话缓存
- 显式禁用 session ticket，避免 benchmark 混入 resumption 收益
- 客户端仍沿用 `SslVerifyMode::None`，结果解释时必须披露

这意味着跨语言对比更接近“TLS 1.3 握手 + 加密 echo”的服务端性能比较，而不是生产安全配置下的端到端真实性能。

## Cross-Language Runner

仓库内提供了一套远端 Linux 基准入口：

```bash
bash scripts/S2-CrossLangBench.sh \
  --remote-host 140.143.142.251 \
  --remote-user ubuntu \
  --remote-password '***' \
  --remote-root /home/ubuntu/tmp/galay-ssl-crosslang-bench \
  --server-cpus 0-1 \
  --client-cpus 2-3 \
  --streaming-connections 64 \
  --streaming-requests 500 \
  --streaming-payload 256 \
  --handshake-connections 128 \
  --handshake-requests 1 \
  --handshake-payload 47 \
  --galay-ssl-workers 4 \
  --build-jobs 1 \
  --threads 4 \
  --warmup-runs 1 \
  --formal-runs 5
```

本地 wrapper 会做三件事：

- 通过 `rsync + ssh` 把当前工作树同步到远端
- 在远端调用 `scripts/S2-CrossLangBench.remote.sh`
- 把远端产出的 CSV / 日志同步回本地输出目录

远端 runner 负责：

- 构建 `galay-kernel` 安装前缀和 `galay-ssl` benchmark 二进制
- 构建 Rust `tokio-rustls` 服务端和 Go `crypto/tls` 服务端
- 对 `streaming` / `handshake` 两类场景先做 probe，再做 warmup 和 formal runs
- 对服务端与客户端分别绑核，避免把远端 CPU 打满
- 通过 `--build-jobs` 限制远端 CMake / Cargo / Go 构建并行度，避免构建阶段把远端 CPU 顶满
- 写出 `raw-results.csv` 与 `summary.csv`

`--galay-ssl-workers` 只影响 `galay-ssl` 的 `B1-SslBenchServer`。如果你想验证 `handshake-heavy` 场景里单 scheduler 与多 worker 的差异，建议把它设置到接近 `--server-cpus` 的 CPU 数。

如果远端环境比较旧，runner 还会做两件兼容处理：

- 对旧版 `cargo` 自动回退到“移除本地 benchmark `Cargo.lock` 后重新生成”
- 对 Go 构建强制使用 `GOTOOLCHAIN=local`，避免远端自动下载新工具链

如果远端还没有 `cargo` / `go`，可以额外带上：

```bash
--bootstrap-toolchains
```

它会先在远端安装缺失工具链，再开始 benchmark。

## 输出指标

客户端输出：

- `Total requests`
- `Total errors`
- `Error breakdown`（仅当错误 > 0）
- `Total bytes sent/received`
- `Duration`
- `Requests/sec`
- `Throughput`

可选统计（仅 benchmark 侧）：

```bash
GALAY_SSL_STATS=1 ./build/bin/B1-SslBenchClient 127.0.0.1 8443 50 200 47 4
```

会额外输出：

- `Send ops / send plain bytes`
- `Recv ops / recv plain bytes / recv chunks`
- `Avg recv chunk bytes`

## 注意事项

- 测试证书为自签名，默认用于开发/测试
- 客户端默认 `SslVerifyMode::None`（压测口径），不是生产安全配置
- 建议统一使用 `Release + LTO`，避免构建口径造成数据偏差
- 默认远端 CPU 绑定建议是 `server=0-1`、`client=2-3`；如果远端规格不同，请按实际 CPU 拓扑调整
