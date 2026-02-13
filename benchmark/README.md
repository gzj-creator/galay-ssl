# galay-ssl 性能测试

本目录包含galay-ssl库的性能测试程序，用于评估SSL/TLS通信的吞吐量和并发性能。

## 测试程序

### B1-SslBenchServer

SSL服务端性能测试程序，模拟echo服务器。

**用法：**
```bash
./build/bin/B1-SslBenchServer <port> <cert_file> <key_file>
```

**参数：**
- `port`: 监听端口
- `cert_file`: SSL证书文件路径
- `key_file`: SSL私钥文件路径

**示例：**
```bash
./build/bin/B1-SslBenchServer 8443 certs/server.crt certs/server.key
```

### B1-SslBenchClient

SSL客户端性能测试程序，模拟多个并发连接。

**用法：**
```bash
./build/bin/B1-SslBenchClient <host> <port> <connections> <requests_per_conn> [payload_bytes] [threads]
```

**参数：**
- `host`: 服务端主机名或IP地址
- `port`: 服务端端口
- `connections`: 并发连接数
- `requests_per_conn`: 每个连接的请求数
- `payload_bytes`: 可选，单次请求发送的 payload 大小（字节）。默认 47 字节（与历史报告一致）。
- `threads`: 可选，客户端压测线程数（默认 1）。

**示例：**
```bash
# 默认 47 字节 payload
./build/bin/B1-SslBenchClient 127.0.0.1 8443 100 1000

# 64KiB 大包压测
./build/bin/B1-SslBenchClient 127.0.0.1 8443 50 200 65536 4
```

## 运行完整测试

1. 生成测试证书（如果还没有生成）：
```bash
bash test/certs/generate_certs.sh
```

2. 启动服务端：
```bash
./build/bin/B1-SslBenchServer 8443 test/certs/server.crt test/certs/server.key
```

3. 在另一个终端启动客户端：
```bash
./build/bin/B1-SslBenchClient 127.0.0.1 8443 50 100
```

历史对照数据（OpenSSL + libevent）已迁移到 `docs/B1-SSL压测报告.md`，
当前仓库仅保留 `B1-SslBenchServer/B1-SslBenchClient` 压测程序。

## 性能指标

客户端程序会输出以下性能指标：
- 总连接数
- 每个连接的请求数
- 总请求数
- 总错误数
- 发送/接收字节数
- 测试持续时间
- QPS (每秒请求数)
- 吞吐量 (MB/s)

可选统计（仅 benchmark 侧，不进入核心库代码路径）：
```bash
GALAY_SSL_STATS=1 ./build/bin/B1-SslBenchClient 127.0.0.1 8443 50 200 47 4
```
会额外输出：
- Send ops / send plain bytes
- Recv ops / recv plain bytes / recv chunks
- Avg recv chunk bytes

服务端程序会实时显示：
- 当前连接数
- 累计接收/发送字节数

## 注意事项

- 测试使用自签名证书，客户端默认跳过证书验证
- 服务端支持多个并发连接
- 客户端按请求粒度发送固定大小 payload（可通过 `payload_bytes` 调整），并会把 echo 读满该长度后再计为一次请求完成
- 程序使用SIGINT/SIGTERM进行优雅关闭
