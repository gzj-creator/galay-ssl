# galay-kernel Compatibility and Benchmark Results

## Compatibility outcome

- `galay-ssl` 已适配当前 `galay-kernel` 的 `io::handleRecv(...)` 新契约。
- 关键变化：`handleRecv` 现在返回 `std::expected<size_t, IOError>`，不再返回带 `data()/size()` 的字节容器。
- 受影响并已修复的路径：
  - `SslRecvAwaitable::RecvCtx::handleComplete(...)`
  - `SslHandshakeAwaitable::HandshakeRecvCtx::handleComplete(...)`
  - `SslShutdownAwaitable::ShutdownRecvCtx::handleComplete(...)`
- 新增 loopback 烟测 `test/T2-SslLoopbackSmoke.cc`，覆盖：
  - TCP 连接
  - SSL 握手
  - 单次 echo
  - 双端关闭

## Verification

- `cmake --build build --parallel`：通过
- `./scripts/check.sh`：通过
- `./build/bin/T1-SslSocketTest`：34/34 通过
- `./build/bin/T2-SslLoopbackSmoke`：通过
- `E1-SslEchoServer-Include` + `E2-SslClient-Include` 端到端烟测：通过

## Benchmarks

### Same-window comparison

测试口径：

- 小包：`200 connections * 500 requests * 47B * 4 threads`
- 大包：`10 connections * 200 requests * 64KiB * 1 thread`
- 握手：`400 connections * 1 request * 47B * 4 threads`

| Runtime | Small QPS | Large Throughput MB/s | Handshake QPS | Errors |
|---|---:|---:|---:|---:|
| `galay-ssl` | 134,158（3轮均值） | 2,355.35（3轮均值） | 1,631.16（3轮均值） | 0 |
| `Go crypto/tls` | 63,749.13 | 637.76 | 1,570.87 | 0 |
| `Rust rustls + tokio` | 117,356.19 | 580.43 | 4,425.66 | 0 |

### Variance note

- `galay-ssl` 小包 QPS 在本轮复测中波动较大，观察到约 `118k ~ 137k` 区间。
- 因为跨语言程序是临时 harness，当前更适合作为结构对比和数量级对比，不适合作为最终公开基准。

## Profiling notes

### `galay-ssl` small-packet server sample

热点主要落在三类：

1. OpenSSL TLS 记录层与 AES-GCM 加解密
2. `SslSendAwaitable::handleComplete(...)` / `SslRecvAwaitable::RecvCtx::handleComplete(...)`
3. `galay-kernel::KqueueScheduler::processPendingCoroutines()` 与 `addCustom/addSend`

结论：

- 小包场景下，`galay-ssl` 已经不是单纯被“多拷贝”拖慢，主要成本在 TLS 记录处理和调度器唤醒/切换。
- benchmark-side `GALAY_SSL_STATS=1` 显示 `100000` 请求对应 `100000` 次 send、`100000` 次 recv，平均 recv chunk 正好 `47B`，说明当前没有明显的应用层分片问题。

### Go small-packet server sample

采样中可见较多：

- `runtime.netpoll`
- `runtime.asmcgocall`
- `read/write`
- 线程等待与调度唤醒

结论：

- 当前临时 Go harness 更明显受 runtime/netpoll 和 goroutine 调度影响。
- 在当前实现口径下，Go 小包和大包都明显慢于 `galay-ssl`。

### Rust small-packet server sample

采样中可见较多：

- `tokio::runtime::scheduler`
- `tokio_rustls::common::Stream::*`
- `rustls::vecbuf::ChunkVecBuffer::write_to`
- `writev`

结论：

- Rust 小包 QPS 接近 `galay-ssl`，说明 tokio + rustls 在小包并发下有较强竞争力。
- Rust 大包吞吐显著落后于 `galay-ssl`，说明当前临时 harness 的大包写回路径更偏向 runtime/IO 适配，而不是极限吞吐。

## Optimization experiments

### Kept change: reuse handshake / shutdown IO buffers

本轮保留了一项低风险优化：

- 将 `SslHandshakeAwaitable` / `SslShutdownAwaitable` 的临时 `16KiB` IO buffer
  改为优先复用 `SslSocket` 持有的持久 buffer
- 目的：减少每连接握手与关闭阶段的临时分配和初始化

保留前后对比（同口径，优化后为 3 轮观察）：

| 指标 | 优化前 | 优化后 |
|---|---:|---:|
| 小包 QPS | 118,906 | 134,158（129,199 / 138,504） |
| 大包吞吐 MB/s | 2,272.73 | 2,355.35（2,173.91 / 2,577.32） |
| 握手 QPS | 1,574.80 | 1,631.16（1,538.46 / 1,702.13） |

结论：

- 小包 QPS 明显改善
- 大包吞吐基本持平，波动在可接受范围
- 握手 QPS 小幅改善

因此该优化保留。

### Rejected change: fewer TLS 1.3 session tickets

尝试过在服务端默认设置更少的 TLS 1.3 ticket，以降低握手后 `NewSessionTicket` 开销。

观察结果：

- 握手 QPS 有提升（约从 `1.57k` 升到 `1.69k`）
- 但小包 QPS 复测稳定下降到约 `104k ~ 125k`

结论：

- 这项改动没有同时满足“小包优先”的目标，因此已回退，不保留在当前结果中。

## Current gap assessment

1. **对 Go**
   - `galay-ssl` 当前在小包和大包场景都明显领先
   - 握手场景两者接近，没有形成明显优势

2. **对 Rust**
   - 小包 QPS 基本同档
   - 大包吞吐 `galay-ssl` 明显领先
   - 握手场景 `rustls + tokio` 明显领先

3. **最值得继续追的差距**
   - 如果目标是 `47B` 小包 QPS：下一轮重点应放在 `galay-kernel` 调度唤醒成本与 `SslSend/SslRecvAwaitable` 状态机调度次数
   - 如果目标是握手：应重点研究 TLS 1.3 握手后 ticket、握手状态机 send/recv 轮转，以及是否要提供更明确的 session reuse benchmark 口径
   - 如果目标是大包吞吐：当前 `galay-ssl` 已经优于这两份临时对标实现，优先级相对较低

## Recommended next steps

1. 为 `galay-ssl` 小包路径增加更细的调度侧计数：
   - `recv wakeups`
   - `send wakeups`
   - `handshake want-read/write`
   - `shutdown extra rounds`

2. 单独为握手场景增加两套口径：
   - full handshake
   - resumed handshake

3. 若要继续追小包 QPS，优先检查：
   - `galay-kernel` `KqueueScheduler::addCustom/addSend/processPendingCoroutines`
   - `SslRecvAwaitable`/`SslSendAwaitable` 是否还有可合并的调度轮次
