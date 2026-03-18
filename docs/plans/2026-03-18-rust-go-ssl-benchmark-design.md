# Rust/Go SSL Server Benchmark Design

## Goal

在严格控制变量的前提下，对比 `galay-ssl`、Rust `tokio-rustls`、Go `crypto/tls` 三种 TLS Echo 服务端实现的性能，并产出可复现的脚本、原始数据和结论。

本次对比只做“服务端口径” benchmark：固定同一个压测客户端，只替换服务端实现，避免把客户端运行时、任务模型和 IO 行为混入结论。

## Scope

### Included

- 新增 Rust `tokio-rustls` TLS Echo benchmark 服务端
- 新增 Go `crypto/tls` TLS Echo benchmark 服务端
- 复用现有 `galay-ssl` benchmark 客户端作为统一压测入口
- 提供统一的本地/远端运行脚本
- 提供统一结果采集、CSV 落盘和结果汇总
- 在远端 Linux 上完成正式对比

### Excluded

- 不做“各语言各自客户端 + 各语言各自服务端”的生态对比
- 不做 OpenSSL 封装路线的 Rust / Go 对比
- 不把证书校验成本纳入正式结论
- 不把 HTTP、ALPN、session resumption、0-RTT 引入本次口径

## Controlled Variables

正式对比必须固定以下变量：

- 同一台远端 Linux 机器
- 同一组服务端证书与私钥
- 同一 TLS 版本口径，优先固定为 TLS 1.3
- 同一 Echo 协议语义：收到多少字节就原样写回多少字节
- 同一客户端：统一使用 `B1-SslBenchClient`
- 同一 payload 大小
- 同一并发连接数
- 同一每连接请求数
- 同一客户端线程数
- 同一连接重试参数
- 同一 backlog
- 同一预热次数和正式采样次数
- 同一 CPU 绑定策略
- 同一结果统计方式，统一取中位数

需要显式披露但不强行统一的变量：

- `galay-ssl` 使用 `epoll`
- Rust / Go 使用各自语言运行时在 Linux 上的默认 netpoll 机制
- 编译器版本与编译参数

## Benchmark Matrix

正式场景分两类：

### Streaming

长连接、多请求、小 payload，重点观察 steady-state QPS 和吞吐。

建议默认口径：

- `connections = 64`
- `requests_per_conn = 500`
- `payload_bytes = 256`
- `threads = 4`
- `connect_retries = 3`

### Handshake-Heavy

短连接、单请求、小 payload，重点观察握手主导场景。

建议默认口径：

- `connections = 128`
- `requests_per_conn = 1`
- `payload_bytes = 47`
- `threads = 4`
- `connect_retries = 3`

最终正式参数不是拍脑袋确定，而是先经过低负载探测，再锁定一档不会把远端 CPU 打满的参数。

## CPU Safety Rules

远端机器不能被打满，执行脚本必须内建保护：

- 服务端和客户端分开绑核，使用互不重叠 CPU 集
- 每轮 benchmark 前先做一次低负载探测
- 只有在探测结果满足阈值时，才进入正式负载
- 正式负载目标：
- 机器整体 CPU 利用率不超过约 `70%`
- 客户端或服务端绑定核组平均利用率不超过约 `80%`
- 若任一实现达到阈值，整体参数统一降档，三种实现保持同一参数
- 所有 benchmark 串行运行，不允许多个服务端同时驻留
- 每轮之间保留冷却间隔，避免短时间内持续高温和调度噪声

## Architecture

### Server Implementations

保留现有 C++ `galay-ssl` benchmark 服务端，并新增两个平行服务端：

- Rust: `tokio` + `tokio-rustls`
- Go: `net` + `crypto/tls`

三者都实现相同协议：

1. 接收 TCP/TLS 连接
2. 完成 TLS 握手
3. 进入循环读写
4. 对每次收到的 payload 原样 echo
5. 对端关闭或出错时退出

### Client

统一复用现有 `benchmark/B1-ssl_bench_client.cc`，不为 Rust / Go 写单独客户端。

这样做有两个好处：

- 被测侧始终是“服务端”
- 请求模型、消息拼装、重试策略、收发统计完全一致

### Orchestration

新增统一运行脚本完成以下流程：

1. 检查依赖与构建产物
2. 选择远端执行参数
3. 启动单个服务端
4. 等待监听 ready
5. 执行 warmup
6. 执行正式采样
7. 采集客户端输出和进程 CPU/RSS
8. 停止服务端
9. 写入原始 CSV / 日志
10. 计算中位数并输出汇总表

## Measurement

### Primary Metrics

- `Requests/sec`
- `Throughput MB/s`
- `Total errors`

### Secondary Metrics

- 服务端进程 CPU
- 客户端进程 CPU
- 服务端 RSS
- 客户端 RSS
- 每轮 duration

### Result Format

结果至少包含两层：

- 原始数据：每轮完整命令、stdout 摘要、CPU/RSS、时间戳、CSV
- 汇总数据：三种实现按场景对比的中位数表

## Remote Execution Environment

正式结果以远端 Linux 为准。

结果文档中必须记录：

- 机器型号 / CPU 信息
- Linux 版本
- 编译器与工具链版本
- OpenSSL 版本
- Rust 版本
- Go 版本
- 具体 commit SHA
- 完整服务端/客户端命令

本地 macOS 结果如果需要，可作为附录参考，不混入正式结论。

## Risks

### Runtime Semantics Are Not Identical

Rust 和 Go 的运行时/调度模型与 `galay-ssl` 不同，无法做到二进制级别的完全同构。对此的处理方式不是回避，而是把口径限制为：

“同机器、同协议、同客户端、同参数下的 TLS Echo 服务端性能对比”。

### Certificate Verification Is Disabled In Current Client Flow

现有 benchmark 客户端延续 `verify none` 口径，这意味着结论更接近“握手 + 加密 echo”的服务端对比，而不是生产安全配置下的端到端真实性能。结果文档必须明确披露这一点。

### CPU Saturation Can Distort Results

如果远端 CPU 打满，调度延迟、accept 抖动和热降频都会污染结果，因此脚本必须先探测负载，再选择正式参数，而不是直接跑历史大并发参数。

## Deliverables

- Rust TLS Echo benchmark 服务端源码
- Go TLS Echo benchmark 服务端源码
- 统一构建与远端运行脚本
- 统一结果采集脚本
- 结果 CSV 与日志
- 性能对比报告文档

## Success Criteria

满足以下条件即可认为本任务完成：

- 三种服务端都能在同一脚本框架下被启动和停止
- 三种服务端都能通过统一客户端完成 streaming 与 handshake-heavy 两类场景
- 全过程不会把远端机器 CPU 打满
- 输出包含原始数据、汇总表和结论
- 结论能明确说明 `galay-ssl` 相对 Rust / Go 的表现与边界
