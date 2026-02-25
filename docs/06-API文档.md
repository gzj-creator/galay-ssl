# 06-API文档

本文中的示例代码默认可配合模块化导入使用：`import galay.ssl;`（不支持模块时按需包含对应头文件，如 `galay-ssl/async/SslSocket.h`）。

## SslContext

定义位置：`galay-ssl/ssl/SslContext.h`

`SslContext` 封装 OpenSSL 的 `SSL_CTX`，负责 TLS 全局配置和证书加载。一个 `SslContext` 可供多个连接共享。

### 构造与生命周期

```cpp
class SslContext {
public:
    explicit SslContext(SslMethod method);
    ~SslContext();

    // 禁用拷贝，支持移动
    SslContext(const SslContext&) = delete;
    SslContext& operator=(const SslContext&) = delete;
    SslContext(SslContext&& other) noexcept;
    SslContext& operator=(SslContext&& other) noexcept;

    bool isValid() const;
    SSL_CTX* native() const;
    const SslError& error() const;
};
```

### SslMethod 枚举

```cpp
enum class SslMethod {
    TLS_Client,     // TLS 客户端（支持 TLS 1.2/1.3）
    TLS_Server,     // TLS 服务端（支持 TLS 1.2/1.3）
    TLS_1_2_Client, // 仅 TLS 1.2 客户端
    TLS_1_2_Server, // 仅 TLS 1.2 服务端
    TLS_1_3_Client, // 仅 TLS 1.3 客户端
    TLS_1_3_Server, // 仅 TLS 1.3 服务端
    DTLS_Client,    // DTLS 客户端
    DTLS_Server,    // DTLS 服务端
};
```

### 证书与密钥管理

```cpp
// 加载证书
std::expected<void, SslError> loadCertificate(
    const std::string& certFile,
    SslFileType type = SslFileType::PEM);

// 加载证书链
std::expected<void, SslError> loadCertificateChain(
    const std::string& certChainFile);

// 加载私钥
std::expected<void, SslError> loadPrivateKey(
    const std::string& keyFile,
    SslFileType type = SslFileType::PEM);

// 加载 CA 证书
std::expected<void, SslError> loadCACertificate(const std::string& caFile);
std::expected<void, SslError> loadCAPath(const std::string& caPath);
std::expected<void, SslError> useDefaultCA();
```

### SslFileType 枚举

```cpp
enum class SslFileType {
    PEM,  // PEM 格式（默认）
    ASN1, // DER/ASN1 格式
};
```

### 证书验证配置

```cpp
// 设置验证模式
void setVerifyMode(
    SslVerifyMode mode,
    std::function<bool(bool, X509_STORE_CTX*)> callback = nullptr);

// 设置验证深度
void setVerifyDepth(int depth);
```

### SslVerifyMode 枚举

```cpp
enum class SslVerifyMode {
    None,               // 不验证证书
    Peer,               // 验证对端证书
    FailIfNoPeerCert,   // 要求对端必须提供证书
    ClientOnce,         // 仅在初始握手时验证客户端
};
```

### 密码套件配置

```cpp
// TLS 1.2 及以下密码套件
std::expected<void, SslError> setCiphers(const std::string& ciphers);

// TLS 1.3 密码套件
std::expected<void, SslError> setCiphersuites(const std::string& ciphersuites);
```

常用密码套件示例：

```cpp
// 高安全性配置（TLS 1.2）
ctx.setCiphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

// TLS 1.3 默认套件
ctx.setCiphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
```

### ALPN 配置

```cpp
// 设置 ALPN 协议列表
std::expected<void, SslError> setALPNProtocols(
    const std::vector<std::string>& protocols);
```

示例：

```cpp
ctx.setALPNProtocols({"h2", "http/1.1"});
```

### 协议版本控制

```cpp
void setMinProtocolVersion(int version);
void setMaxProtocolVersion(int version);
```

OpenSSL 版本常量：

- `TLS1_VERSION`：TLS 1.0
- `TLS1_1_VERSION`：TLS 1.1
- `TLS1_2_VERSION`：TLS 1.2
- `TLS1_3_VERSION`：TLS 1.3

示例：

```cpp
ctx.setMinProtocolVersion(TLS1_2_VERSION);
ctx.setMaxProtocolVersion(TLS1_3_VERSION);
```

### Session 缓存配置

```cpp
// 设置 Session 缓存模式
void setSessionCacheMode(long mode);

// 设置 Session 超时时间（秒）
void setSessionTimeout(long timeout);
```

OpenSSL Session 缓存模式：

- `SSL_SESS_CACHE_OFF`：禁用缓存
- `SSL_SESS_CACHE_CLIENT`：客户端缓存
- `SSL_SESS_CACHE_SERVER`：服务端缓存
- `SSL_SESS_CACHE_BOTH`：双向缓存

示例：

```cpp
ctx.setSessionCacheMode(SSL_SESS_CACHE_CLIENT);
ctx.setSessionTimeout(300); // 5 分钟
```

## SslEngine

定义位置：`galay-ssl/ssl/SslEngine.h`

`SslEngine` 对应单条 TLS 连接，负责调用 OpenSSL 进行握手和加解密。它本身不直接做网络 IO，而是通过 Memory BIO 与外部 IO 层交换密文。

### 核心接口

```cpp
class SslEngine {
public:
    SslEngine();
    explicit SslEngine(SslContext* ctx);
    ~SslEngine();

    // 禁用拷贝，支持移动
    SslEngine(const SslEngine&) = delete;
    SslEngine& operator=(const SslEngine&) = delete;
    SslEngine(SslEngine&& other) noexcept;
    SslEngine& operator=(SslEngine&& other) noexcept;

    bool isValid() const;
    bool isHandshakeCompleted() const;
    SSL* native() const;
};
```

### 初始化与模式设置

```cpp
// 初始化 Memory BIO
bool initMemoryBIO();

// 设置客户端模式
void setConnectState();

// 设置服务端模式
void setAcceptState();
```

### 握手操作

```cpp
enum class SslHandshakeResult {
    Success,      // 握手成功
    WantRead,     // 需要读取网络数据
    WantWrite,    // 需要发送网络数据
    Error,        // 握手失败
    ZeroReturn,   // 连接关闭
};

SslHandshakeResult doHandshake();
```

### 数据读写

```cpp
// 读取明文数据
std::expected<std::span<const uint8_t>, SslError> read(
    std::span<uint8_t> buffer);

// 写入明文数据
std::expected<size_t, SslError> write(
    std::span<const uint8_t> data);
```

### Memory BIO 操作

```cpp
// 将网络密文喂给 SSL 引擎
size_t feedEncryptedInput(std::span<const uint8_t> data);

// 从 SSL 引擎提取待发送密文
std::span<const uint8_t> extractEncryptedOutput(
    std::span<uint8_t> buffer);

// 查询待发送密文大小
size_t pendingEncryptedOutput() const;
```

### 连接信息查询

```cpp
// 获取协议版本
std::string getProtocolVersion() const;

// 获取密码套件
std::string getCipher() const;

// 获取 ALPN 协议
std::string getALPNProtocol() const;
```

### Session 管理

```cpp
// 获取当前 Session（调用者需要 SSL_SESSION_free）
SSL_SESSION* getSession() const;

// 设置 Session（用于复用）
bool setSession(SSL_SESSION* session);

// 检查是否复用了 Session
bool isSessionReused() const;
```

### 证书验证

```cpp
// 获取对端证书（调用者需要 X509_free）
X509* getPeerCertificate() const;

// 获取证书验证结果
long getVerifyResult() const;
```

验证结果常量：

- `X509_V_OK`：验证成功
- `X509_V_ERR_CERT_HAS_EXPIRED`：证书过期
- `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT`：自签名证书
- `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT`：无法获取颁发者证书

### 关闭操作

```cpp
enum class SslShutdownResult {
    Success,      // 关闭成功
    WantRead,     // 需要读取
    WantWrite,    // 需要写入
    Error,        // 关闭失败
};

SslShutdownResult shutdown();
```

## SslSocket

定义位置：`galay-ssl/async/SslSocket.h`

`SslSocket` 是面向业务的高层 API，内部组合 `IOController + SslEngine`，把 TCP + TLS 行为统一成协程友好接口。

### 构造与生命周期

```cpp
class SslSocket {
public:
    // 创建新 Socket
    SslSocket(SslContext* ctx, IPType type = IPType::IPV4);

    // 从已有句柄构造（用于 accept）
    SslSocket(SslContext* ctx, GHandle handle);

    ~SslSocket();

    // 禁用拷贝，支持移动
    SslSocket(const SslSocket&) = delete;
    SslSocket& operator=(const SslSocket&) = delete;
    SslSocket(SslSocket&& other) noexcept;
    SslSocket& operator=(SslSocket&& other) noexcept;

    GHandle handle() const;
    IOController* controller();
    SslEngine* engine();
    bool isValid() const;
    bool isHandshakeCompleted() const;
};
```

### 服务端操作

```cpp
// 绑定地址
std::expected<void, IOError> bind(const Host& host);

// 开始监听
std::expected<void, IOError> listen(int backlog = 128);

// 接受新连接
AcceptAwaitable accept(Host* clientHost);
```

### 客户端操作

```cpp
// 设置 SNI 主机名
std::expected<void, SslError> setHostname(const std::string& hostname);

// 连接服务器
ConnectAwaitable connect(const Host& host);
```

### TLS 握手

```cpp
// 执行 SSL 握手
SslHandshakeAwaitable handshake();
```

### 数据传输

```cpp
// 接收数据
SslRecvAwaitable recv(char* buffer, size_t length);

// 发送数据
SslSendAwaitable send(const char* buffer, size_t length);
```

### 连接关闭

```cpp
// SSL 关闭握手
SslShutdownAwaitable shutdown();

// 关闭底层 socket
CloseAwaitable close();
```

### Socket 选项

```cpp
HandleOption option();
```

常用选项：

```cpp
socket.option().handleNonBlock();      // 设置非阻塞
socket.option().handleReuseAddr();     // 地址复用
socket.option().handleReusePort();     // 端口复用
socket.option().handleKeepAlive();     // TCP Keep-Alive
socket.option().handleNoDelay();       // 禁用 Nagle 算法
```

### 连接信息查询

```cpp
// 获取对端证书
X509* getPeerCertificate() const;

// 获取证书验证结果
long getVerifyResult() const;

// 获取协议版本
std::string getProtocolVersion() const;

// 获取密码套件
std::string getCipher() const;

// 获取 ALPN 协议
std::string getALPNProtocol() const;
```

### Session 管理

```cpp
// 设置 Session
bool setSession(SSL_SESSION* session);

// 获取 Session
SSL_SESSION* getSession() const;

// 检查是否复用
bool isSessionReused() const;
```

## Awaitable 类型

定义位置：`galay-ssl/async/Awaitable.h`

### SslHandshakeAwaitable

```cpp
class SslHandshakeAwaitable {
public:
    // 协程接口
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> handle);
    std::expected<void, SslError> await_resume();
};
```

使用示例：

```cpp
while (!socket.isHandshakeCompleted()) {
    auto result = co_await socket.handshake();
    if (!result) {
        std::cerr << "Handshake failed: " << result.error().message() << '\n';
        co_return;
    }
}
```

### SslRecvAwaitable

```cpp
class SslRecvAwaitable {
public:
    // 协程接口
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> handle);
    std::expected<std::span<const uint8_t>, SslError> await_resume();

    // 超时支持
    auto timeout(std::chrono::milliseconds ms);
};
```

使用示例：

```cpp
char buffer[4096];
auto result = co_await socket.recv(buffer, sizeof(buffer));
if (!result) {
    std::cerr << "Recv failed: " << result.error().message() << '\n';
    co_return;
}

auto data = result.value();
std::cout << "Received " << data.size() << " bytes\n";
```

### SslSendAwaitable

```cpp
class SslSendAwaitable {
public:
    // 协程接口
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> handle);
    std::expected<size_t, SslError> await_resume();

    // 超时支持
    auto timeout(std::chrono::milliseconds ms);
};
```

使用示例：

```cpp
const char* msg = "Hello, SSL!";
auto result = co_await socket.send(msg, strlen(msg));
if (!result) {
    std::cerr << "Send failed: " << result.error().message() << '\n';
    co_return;
}

std::cout << "Sent " << result.value() << " bytes\n";
```

### SslShutdownAwaitable

```cpp
class SslShutdownAwaitable {
public:
    // 协程接口
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> handle);
    std::expected<void, SslError> await_resume();
};
```

使用示例：

```cpp
auto result = co_await socket.shutdown();
if (!result) {
    std::cerr << "Shutdown failed: " << result.error().message() << '\n';
}
```

## 错误处理

定义位置：`galay-ssl/common/Error.h`

### SslError

```cpp
class SslError {
public:
    SslError();
    explicit SslError(SslErrorCode code, unsigned long ssl_error = 0);

    static SslError fromOpenSSL(SslErrorCode code);

    bool isSuccess() const;
    bool needsRetry() const;
    SslErrorCode code() const;
    unsigned long sslError() const;
    std::string message() const;
    std::string sslErrorString() const;
};
```

### SslErrorCode 枚举

```cpp
enum class SslErrorCode : uint32_t {
    kSuccess,                   // 成功
    kContextCreateFailed,       // SSL 上下文创建失败
    kCertificateLoadFailed,     // 证书加载失败
    kPrivateKeyLoadFailed,      // 私钥加载失败
    kPrivateKeyMismatch,        // 私钥与证书不匹配
    kCACertificateLoadFailed,   // CA 证书加载失败
    kSslCreateFailed,           // SSL 对象创建失败
    kSslSetFdFailed,            // 设置 SSL fd 失败
    kHandshakeFailed,           // 握手失败
    kHandshakeTimeout,          // 握手超时
    kHandshakeWantRead,         // 握手需要读取
    kHandshakeWantWrite,        // 握手需要写入
    kReadFailed,                // 读取失败
    kWriteFailed,               // 写入失败
    kShutdownFailed,            // 关闭失败
    kPeerClosed,                // 对端关闭
    kVerificationFailed,        // 证书验证失败
    kSNISetFailed,              // SNI 设置失败
    kALPNSetFailed,             // ALPN 设置失败
    kTimeout,                   // 操作超时
    kUnknown,                   // 未知错误
};
```

### 错误处理示例

```cpp
auto result = co_await socket.handshake();
if (!result) {
    const auto& err = result.error();
    std::cerr << "Error code: " << static_cast<int>(err.code()) << '\n';
    std::cerr << "Message: " << err.message() << '\n';

    if (err.sslError() != 0) {
        std::cerr << "OpenSSL error: " << err.sslErrorString() << '\n';
    }

    if (err.needsRetry()) {
        // 可重试错误
    }

    co_return;
}
```

## 使用注意事项

### SslContext

1. **线程安全**：`SSL_CTX` 本身是线程安全的，可以在多个线程中共享
2. **生命周期**：必须在所有使用它的 `SslSocket` 销毁前保持有效
3. **证书加载**：服务端必须加载证书和私钥，客户端可选

### SslSocket

1. **非阻塞模式**：必须调用 `option().handleNonBlock()` 设置非阻塞
2. **握手顺序**：`connect` 或 `accept` 后必须先 `handshake` 再收发数据
3. **显式关闭**：析构不会自动关闭，必须显式 `co_await close()`
4. **移动语义**：支持移动，可以在容器中存储或传递

### 协程使用

1. **串行操作**：同一个 `SslSocket` 应串行执行操作，不要并发调用
2. **错误检查**：每个 `co_await` 都应检查返回值
3. **超时设置**：生产环境建议为 `recv/send` 设置超时
4. **资源清理**：确保异常路径也能正确关闭连接

### 性能优化

1. **Session 复用**：客户端使用 Session 复用可减少握手开销
2. **连接池**：频繁连接场景建议实现连接池
3. **缓冲区大小**：根据实际负载调整接收缓冲区大小
4. **密码套件**：选择硬件加速支持的密码套件（如 AES-NI）
