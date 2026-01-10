# galay-ssl 性能测试

本目录包含galay-ssl库的性能测试程序，用于评估SSL/TLS通信的吞吐量和并发性能。

## 测试程序

### bench_ssl_server

SSL服务端性能测试程序，模拟echo服务器。

**用法：**
```bash
./bench_ssl_server <port> <cert_file> <key_file>
```

**参数：**
- `port`: 监听端口
- `cert_file`: SSL证书文件路径
- `key_file`: SSL私钥文件路径

**示例：**
```bash
./bench_ssl_server 8443 certs/server.crt certs/server.key
```

### bench_ssl_client

SSL客户端性能测试程序，模拟多个并发连接。

**用法：**
```bash
./bench_ssl_client <host> <port> <connections> <requests_per_conn>
```

**参数：**
- `host`: 服务端主机名或IP地址
- `port`: 服务端端口
- `connections`: 并发连接数
- `requests_per_conn`: 每个连接的请求数

**示例：**
```bash
./bench_ssl_client 127.0.0.1 8443 100 1000
```

## 运行完整测试

1. 生成测试证书（如果还没有生成）：
```bash
cd ../test/certs
bash generate_certs.sh
```

2. 启动服务端：
```bash
./bench_ssl_server 8443 ../test/certs/server.crt ../test/certs/server.key
```

3. 在另一个终端启动客户端：
```bash
./bench_ssl_client 127.0.0.1 8443 50 100
```

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

服务端程序会实时显示：
- 当前连接数
- 累计接收/发送字节数

## 注意事项

- 测试使用自签名证书，客户端默认跳过证书验证
- 服务端支持多个并发连接
- 客户端使用固定消息大小进行echo测试
- 程序使用SIGINT/SIGTERM进行优雅关闭
