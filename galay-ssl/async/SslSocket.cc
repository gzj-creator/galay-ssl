#include "SslSocket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

namespace galay::ssl
{

SslSocket::SslSocket(SslContext* ctx, IPType type)
    : m_controller(GHandle::invalid())
    , m_ctx(ctx)
    , m_engine(ctx)
    , m_isServer(false)
{
    int domain = (type == IPType::IPV4) ? AF_INET : AF_INET6;
    int fd = ::socket(domain, SOCK_STREAM, 0);
    if (fd >= 0) {
        m_controller.m_handle.fd = fd;
    }
}

SslSocket::SslSocket(SslContext* ctx, GHandle handle)
    : m_controller(handle)
    , m_ctx(ctx)
    , m_engine(ctx)
    , m_isServer(true)
{
    initEngine();
}

SslSocket::~SslSocket()
{
    // 不自动关闭，需要显式调用 close()
}

SslSocket::SslSocket(SslSocket&& other) noexcept
    : m_controller(std::move(other.m_controller))
    , m_ctx(other.m_ctx)
    , m_engine(std::move(other.m_engine))
    , m_isServer(other.m_isServer)
{
    other.m_ctx = nullptr;
}

SslSocket& SslSocket::operator=(SslSocket&& other) noexcept
{
    if (this != &other) {
        m_controller = std::move(other.m_controller);
        m_ctx = other.m_ctx;
        m_engine = std::move(other.m_engine);
        m_isServer = other.m_isServer;

        other.m_ctx = nullptr;
    }
    return *this;
}

std::expected<void, IOError> SslSocket::bind(const Host& host)
{
    if (::bind(m_controller.m_handle.fd, host.sockAddr(), host.addrLen()) < 0) {
        return std::unexpected(IOError(IOErrorCode::kBindFailed, errno));
    }
    return {};
}

std::expected<void, IOError> SslSocket::listen(int backlog)
{
    if (::listen(m_controller.m_handle.fd, backlog) < 0) {
        return std::unexpected(IOError(IOErrorCode::kListenFailed, errno));
    }

    m_isServer = true;
    return {};
}

std::expected<void, SslError> SslSocket::setHostname(const std::string& hostname)
{
    return m_engine.setHostname(hostname);
}

void SslSocket::initEngine()
{
    if (m_controller.m_handle.fd >= 0 && m_engine.isValid()) {
        (void)m_engine.setFd(m_controller.m_handle.fd);
        if (m_isServer) {
            m_engine.setAcceptState();
        } else {
            m_engine.setConnectState();
        }
    }
}

AcceptAwaitable SslSocket::accept(Host* clientHost)
{
    return AcceptAwaitable(&m_controller, clientHost);
}

ConnectAwaitable SslSocket::connect(const Host& host)
{
    // 连接前初始化 SSL 引擎为客户端模式
    m_isServer = false;
    initEngine();

    return ConnectAwaitable(&m_controller, host);
}

SslHandshakeAwaitable SslSocket::handshake()
{
    // 确保 SSL 引擎已初始化
    if (!m_engine.isValid()) {
        initEngine();
    } else if (m_controller.m_handle.fd >= 0) {
        // 确保 fd 已设置
        (void)m_engine.setFd(m_controller.m_handle.fd);
    }

    return SslHandshakeAwaitable(&m_controller, &m_engine);
}

SslRecvAwaitable SslSocket::recv(char* buffer, size_t length)
{
    return SslRecvAwaitable(&m_controller, &m_engine, buffer, length);
}

SslSendAwaitable SslSocket::send(const char* buffer, size_t length)
{
    return SslSendAwaitable(&m_controller, &m_engine, buffer, length);
}

SslShutdownAwaitable SslSocket::shutdown()
{
    return SslShutdownAwaitable(&m_controller, &m_engine);
}

CloseAwaitable SslSocket::close()
{
    return CloseAwaitable(&m_controller);
}

} // namespace galay::ssl
