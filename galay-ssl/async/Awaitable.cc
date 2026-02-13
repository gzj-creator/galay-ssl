#include "Awaitable.h"
#include <cerrno>
#include <algorithm>
#include <sys/event.h>
#include <iostream>
#include <unistd.h>

namespace galay::ssl
{

static constexpr size_t kCipherBufSize = 16384;

// ==================== SslRecvAwaitable ====================

SslRecvAwaitable::SslRecvAwaitable(IOController* controller, SslEngine* engine,
                                   char* buffer, size_t length)
    : RecvAwaitable(controller, nullptr, 0)  // 基类 buffer 稍后指向 m_cipherBuffer
    , m_engine(engine)
    , m_plainBuffer(buffer)
    , m_plainLength(length)
    , m_cipherBuffer(kCipherBufSize)
{
    // 让基类的 raw recv 读到内部密文 buffer
    RecvIOContext::m_buffer = m_cipherBuffer.data();
    RecvIOContext::m_length = m_cipherBuffer.size();
}

#ifdef USE_IOURING
bool SslRecvAwaitable::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    auto result = io::handleRecv(cqe, RecvIOContext::m_buffer);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
        m_sslResultSet = true;
        return true;
    }

    auto& bytes = result.value();
    m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    size_t bytesRead = 0;
    SslIOResult sslRet = m_engine->read(m_plainBuffer, m_plainLength, bytesRead);

    if (sslRet == SslIOResult::Success) {
        m_sslResult = Bytes(m_plainBuffer, bytesRead);
        m_sslResultSet = true;
        return true;
    } else if (sslRet == SslIOResult::WantRead) {
        return false;
    } else if (sslRet == SslIOResult::ZeroReturn) {
        m_sslResult = Bytes();
        m_sslResultSet = true;
        return true;
    } else {
        m_sslResult = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
        m_sslResultSet = true;
        return true;
    }
}
#else
bool SslRecvAwaitable::handleComplete(GHandle handle)
{
    // NOTE: 某些调度器使用边沿触发（如 kqueue EV_CLEAR / epoll ET）。
    // 如果一次回调里不把 socket recv 到 EAGAIN，可能会“吃掉边沿”，导致后续没有事件，从而卡住。
    while (true) {
        auto result = io::handleRecv(handle, RecvIOContext::m_buffer, RecvIOContext::m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            std::cerr << "[SSL-RECV] EAGAIN fd=" << handle.fd << std::endl;
            return false;
        }
        if (!result) {
            std::cerr << "[SSL-RECV] error=" << result.error().message() << " fd=" << handle.fd << std::endl;
            if (IOError::contains(result.error().code(), kDisconnectError)) {
                m_sslResult = Bytes();
            } else {
                m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
            }
            m_sslResultSet = true;
            return true;
        }

        auto& bytes = result.value();
        std::cerr << "[SSL-RECV] raw=" << bytes.size() << " fd=" << handle.fd << std::endl;
        m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());

        // 尝试解密；如果仍 WantRead，则继续 raw recv 直到 EAGAIN
        while (true) {
            size_t bytesRead = 0;
            SslIOResult sslRet = m_engine->read(m_plainBuffer, m_plainLength, bytesRead);
            std::cerr << "[SSL-RECV] SSL_read=" << static_cast<int>(sslRet) << " plain=" << bytesRead << std::endl;

            if (sslRet == SslIOResult::Success && bytesRead > 0) {
                m_sslResult = Bytes(m_plainBuffer, bytesRead);
                m_sslResultSet = true;
                return true;
            }
            if (sslRet == SslIOResult::WantRead) {
                break;  // 需要更多密文，回到外层继续 raw recv
            }
            if (sslRet == SslIOResult::ZeroReturn) {
                m_sslResult = Bytes();
                m_sslResultSet = true;
                return true;
            }

            // WantWrite / Error / Syscall 直接返回错误（需要更复杂的 send/recv 协同）
            m_sslResult = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
            m_sslResultSet = true;
            return true;
        }
    }
}
#endif

bool SslRecvAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    // 先尝试 SSL_read：握手阶段可能已经从网络读取了包含应用数据的密文并喂入了 BIO，
    // 此时 SSL_pending() 返回 0（数据在 BIO 中尚未解密），但 SSL_read 可以解密它。
    size_t bytesRead = 0;
    SslIOResult sslRet = m_engine->read(m_plainBuffer, m_plainLength, bytesRead);
    if (sslRet == SslIOResult::Success && bytesRead > 0) {
        m_sslResult = Bytes(m_plainBuffer, bytesRead);
        m_sslResultSet = true;
        return false;
    }

    return RecvAwaitable::await_suspend(handle);
}

std::expected<Bytes, SslError> SslRecvAwaitable::await_resume()
{
    if (m_sslResultSet) {
        m_controller->removeAwaitable(IOEventType::RECV);
        return std::move(m_sslResult);
    }

    RecvAwaitable::await_resume();
    m_controller->removeAwaitable(IOEventType::RECV);

    if (m_sslResultSet) {
        return std::move(m_sslResult);
    }

    return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
}

// ==================== SslSendAwaitable ====================

SslSendAwaitable::SslSendAwaitable(IOController* controller, SslEngine* engine,
                                   const char* buffer, size_t length)
    : SendAwaitable(controller, nullptr, 0)
    , m_engine(engine)
    , m_plainLength(length)
    , m_cipherBuffer()
{
    // NOTE:
    // - SSL_write 可能发生 partial write（ret > 0 但 ret < length）。
    // - wbio 可能积累多个 TLS record（长度 > 明文长度 + 常数开销）。
    // 因此这里把所有明文都写进 SSL，并把 wbio 里的密文全部 drain 到 m_cipherBuffer，
    // 再交给底层 raw send 一次性发送。

    m_cipherBuffer.reserve(length + 2048);

    auto drainWbio = [&]() -> bool {
        // 防止极端情况下死循环（理论上 pending>0 时 BIO_read 不应一直返回 0）
        int emptyReads = 0;
        while (true) {
            size_t pending = m_engine->pendingEncryptedOutput();
            if (pending == 0) {
                return true;
            }

            size_t oldSize = m_cipherBuffer.size();
            m_cipherBuffer.resize(oldSize + pending);

            int n = m_engine->extractEncryptedOutput(m_cipherBuffer.data() + oldSize, pending);
            if (n > 0) {
                m_cipherBuffer.resize(oldSize + static_cast<size_t>(n));
                emptyReads = 0;
                continue;
            }

            // 没读到数据，回退 resize 并退出（视为错误）
            m_cipherBuffer.resize(oldSize);
            if (++emptyReads > 2) {
                return false;
            }
        }
    };

    // 先收集 wbio 中已有的待发送数据（如 TLS 1.3 post-handshake 消息）
    if (!drainWbio()) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
        m_sslResultSet = true;
        return;
    }

    // SSL_write 加密明文到 wbio（循环直到全部写入）
    size_t totalWritten = 0;
    while (totalWritten < length) {
        size_t bytesWritten = 0;
        SslIOResult sslRet = m_engine->write(buffer + totalWritten, length - totalWritten, bytesWritten);
        std::cerr << "[SSL-SEND] SSL_write ret=" << static_cast<int>(sslRet)
                  << " written=" << bytesWritten
                  << " total=" << (totalWritten + bytesWritten) << "/" << length << std::endl;

        if (sslRet != SslIOResult::Success || bytesWritten == 0) {
            m_sslResult = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kWriteFailed));
            m_sslResultSet = true;
            return;
        }

        totalWritten += bytesWritten;

        if (!drainWbio()) {
            m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
            m_sslResultSet = true;
            return;
        }
    }

    // 最后再 drain 一次，确保没有遗留密文
    if (!drainWbio()) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
        m_sslResultSet = true;
        return;
    }

    if (m_cipherBuffer.empty()) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
        m_sslResultSet = true;
        return;
    }

    SendIOContext::m_buffer = m_cipherBuffer.data();
    SendIOContext::m_length = m_cipherBuffer.size();
    m_cipherLength = m_cipherBuffer.size();
}

#ifdef USE_IOURING
bool SslSendAwaitable::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    auto result = io::handleSend(cqe);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
        m_sslResultSet = true;
        return true;
    }

    m_sslResult = m_plainLength;
    m_sslResultSet = true;
    return true;
}
#else
bool SslSendAwaitable::handleComplete(GHandle handle)
{
    // 同 recv：尽量在一次回调里把数据 send 到 EAGAIN，避免边沿触发场景卡住
    while (SendIOContext::m_length > 0) {
        auto result = io::handleSend(handle, SendIOContext::m_buffer, SendIOContext::m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            std::cerr << "[SSL-SEND] EAGAIN fd=" << handle.fd << std::endl;
            return false;
        }
        if (!result) {
            std::cerr << "[SSL-SEND] error fd=" << handle.fd << std::endl;
            m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
            m_sslResultSet = true;
            return true;
        }

        size_t sent = result.value();
        std::cerr << "[SSL-SEND] sent=" << sent << "/" << SendIOContext::m_length << " fd=" << handle.fd << std::endl;
        if (sent == 0) {
            return false;
        }
        SendIOContext::m_buffer += sent;
        SendIOContext::m_length -= sent;
    }

    m_sslResult = m_plainLength;
    m_sslResultSet = true;
    return true;
}
#endif

bool SslSendAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    if (m_sslResultSet) {
        std::cerr << "[SSL-SEND] await_suspend: already set, not suspending" << std::endl;
        return false;
    }

    std::cerr << "[SSL-SEND] await_suspend: suspending, cipher=" << m_cipherLength << std::endl;
    return SendAwaitable::await_suspend(handle);
}

std::expected<size_t, SslError> SslSendAwaitable::await_resume()
{
    if (m_sslResultSet) {
        m_controller->removeAwaitable(IOEventType::SEND);
        return std::move(m_sslResult);
    }

    SendAwaitable::await_resume();
    m_controller->removeAwaitable(IOEventType::SEND);

    if (m_sslResultSet) {
        return std::move(m_sslResult);
    }

    return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kWriteFailed));
}

// ==================== SslHandshakeAwaitable ====================

SslHandshakeAwaitable::SslHandshakeAwaitable(IOController* controller, SslEngine* engine)
    : CustomAwaitable(controller)
    , m_engine(engine)
    , m_ioBuf(kCipherBufSize)
    , m_recvCtx(m_ioBuf.data(), m_ioBuf.size(), this)
    , m_sendCtx(m_ioBuf.data(), 0, this)
{
    tryHandshake();
}

bool SslHandshakeAwaitable::await_ready()
{
    return m_resultSet;
}

void SslHandshakeAwaitable::tryHandshake()
{
    SslIOResult ret = m_engine->doHandshake();
    std::cerr << "[SSL-HS] tryHandshake ret=" << static_cast<int>(ret)
              << " pendingOut=" << m_engine->pendingEncryptedOutput() << std::endl;

    switch (ret) {
        case SslIOResult::Success: {
            // 握手成功，但可能有待发送的加密数据（如 TLS 1.3 NewSessionTicket）
            size_t pending = m_engine->pendingEncryptedOutput();
            if (pending > 0) {
                if (pending > m_ioBuf.size()) {
                    m_ioBuf.resize(pending);
                }
                int n = m_engine->extractEncryptedOutput(m_ioBuf.data(), m_ioBuf.size());
                if (n > 0) {
                    m_sendCtx.m_buffer = m_ioBuf.data();
                    m_sendCtx.m_length = static_cast<size_t>(n);
                    m_sendCtx.m_followedByRecv = false;
                    m_result = {};
                    m_handshakeSucceeded = true;
                    addTask(IOEventType::SEND, &m_sendCtx);
                    return;
                }
            }
            m_result = {};
            m_resultSet = true;
            return;
        }

        case SslIOResult::WantWrite: {
            size_t pending = m_engine->pendingEncryptedOutput();
            if (pending > m_ioBuf.size()) {
                m_ioBuf.resize(pending);
            }
            int n = m_engine->extractEncryptedOutput(m_ioBuf.data(), m_ioBuf.size());
            if (n > 0) {
                m_sendCtx.m_buffer = m_ioBuf.data();
                m_sendCtx.m_length = static_cast<size_t>(n);
                m_sendCtx.m_followedByRecv = false;
                addTask(IOEventType::SEND, &m_sendCtx);
            } else {
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
                m_resultSet = true;
            }
            return;
        }

        case SslIOResult::WantRead: {
            size_t pending = m_engine->pendingEncryptedOutput();
            if (pending > 0) {
                if (pending > m_ioBuf.size()) {
                    m_ioBuf.resize(pending);
                }
                int n = m_engine->extractEncryptedOutput(m_ioBuf.data(), m_ioBuf.size());
                if (n > 0) {
                    m_sendCtx.m_buffer = m_ioBuf.data();
                    m_sendCtx.m_length = static_cast<size_t>(n);
                    m_sendCtx.m_followedByRecv = true;
                    addTask(IOEventType::SEND, &m_sendCtx);
                }
            }
            m_recvCtx.m_buffer = m_ioBuf.data();
            m_recvCtx.m_length = m_ioBuf.size();
            addTask(IOEventType::RECV, &m_recvCtx);
            return;
        }

        case SslIOResult::ZeroReturn:
            m_result = std::unexpected(SslError(SslErrorCode::kPeerClosed));
            m_resultSet = true;
            return;

        default:
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kHandshakeFailed));
            m_resultSet = true;
            return;
    }
}

std::expected<void, SslError> SslHandshakeAwaitable::await_resume()
{
    onCompleted();
    return std::move(m_result);
}

// --- HandshakeRecvCtx ---

#ifdef USE_IOURING
bool SslHandshakeAwaitable::HandshakeRecvCtx::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    auto result = io::handleRecv(cqe, m_buffer);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        m_owner->m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
        m_owner->m_resultSet = true;
        return true;
    }

    auto& bytes = result.value();
    m_owner->m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    m_owner->tryHandshake();
    return true;
}
#else
bool SslHandshakeAwaitable::HandshakeRecvCtx::handleComplete(GHandle handle)
{
    // 尽量读到 EAGAIN，避免边沿触发吃事件
    bool fedAny = false;
    while (true) {
        auto result = io::handleRecv(handle, m_buffer, m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            std::cerr << "[SSL-HS-RECV] EAGAIN fd=" << handle.fd << std::endl;
            break;
        }
        if (!result) {
            std::cerr << "[SSL-HS-RECV] error fd=" << handle.fd << std::endl;
            m_owner->m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
            m_owner->m_resultSet = true;
            return true;
        }

        auto& bytes = result.value();
        std::cerr << "[SSL-HS-RECV] got=" << bytes.size() << " fd=" << handle.fd << std::endl;
        m_owner->m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        fedAny = true;
    }

    if (fedAny) {
        m_owner->tryHandshake();
        return true;
    }
    return false;
}
#endif

// --- HandshakeSendCtx ---

#ifdef USE_IOURING
bool SslHandshakeAwaitable::HandshakeSendCtx::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    auto result = io::handleSend(cqe);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        m_owner->m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
        m_owner->m_resultSet = true;
        return true;
    }

    if (m_owner->m_handshakeSucceeded) {
        // 握手已成功，这是发送剩余密文（如 NewSessionTicket），发送完成即可
        m_owner->m_resultSet = true;
        return true;
    }

    if (!m_followedByRecv && !m_owner->m_resultSet) {
        m_owner->tryHandshake();
    }
    return true;
}
#else
bool SslHandshakeAwaitable::HandshakeSendCtx::handleComplete(GHandle handle)
{
    while (m_length > 0) {
        auto result = io::handleSend(handle, m_buffer, m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            std::cerr << "[SSL-HS-SEND] EAGAIN fd=" << handle.fd << std::endl;
            return false;
        }
        if (!result) {
            std::cerr << "[SSL-HS-SEND] error fd=" << handle.fd << std::endl;
            m_owner->m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
            m_owner->m_resultSet = true;
            return true;
        }

        size_t sent = result.value();
        std::cerr << "[SSL-HS-SEND] sent=" << sent << "/" << m_length << " followedByRecv=" << m_followedByRecv << " fd=" << handle.fd << std::endl;
        if (sent == 0) {
            return false;
        }
        m_buffer += sent;
        m_length -= sent;
    }

    if (m_owner->m_handshakeSucceeded) {
        // 握手已成功，这是发送剩余密文（如 NewSessionTicket），发送完成即可
        m_owner->m_resultSet = true;
        return true;
    }

    if (!m_followedByRecv && !m_owner->m_resultSet) {
        m_owner->tryHandshake();
    }
    return true;
}
#endif

// ==================== SslShutdownAwaitable ====================

SslShutdownAwaitable::SslShutdownAwaitable(IOController* controller, SslEngine* engine)
    : CustomAwaitable(controller)
    , m_engine(engine)
    , m_ioBuf(kCipherBufSize)
    , m_recvCtx(m_ioBuf.data(), m_ioBuf.size(), this)
    , m_sendCtx(m_ioBuf.data(), 0, this)
{
    tryShutdown();
}

bool SslShutdownAwaitable::await_ready()
{
    return m_resultSet;
}

void SslShutdownAwaitable::tryShutdown()
{
    SslIOResult ret = m_engine->shutdown();

    switch (ret) {
        case SslIOResult::Success:
            m_result = {};
            m_resultSet = true;
            return;

        case SslIOResult::WantWrite: {
            size_t pending = m_engine->pendingEncryptedOutput();
            if (pending > m_ioBuf.size()) {
                m_ioBuf.resize(pending);
            }
            int n = m_engine->extractEncryptedOutput(m_ioBuf.data(), m_ioBuf.size());
            if (n > 0) {
                m_sendCtx.m_buffer = m_ioBuf.data();
                m_sendCtx.m_length = static_cast<size_t>(n);
                m_sendCtx.m_followedByRecv = false;
                addTask(IOEventType::SEND, &m_sendCtx);
            } else {
                m_result = {};
                m_resultSet = true;
            }
            return;
        }

        case SslIOResult::WantRead: {
            size_t pending = m_engine->pendingEncryptedOutput();
            if (pending > 0) {
                if (pending > m_ioBuf.size()) {
                    m_ioBuf.resize(pending);
                }
                int n = m_engine->extractEncryptedOutput(m_ioBuf.data(), m_ioBuf.size());
                if (n > 0) {
                    m_sendCtx.m_buffer = m_ioBuf.data();
                    m_sendCtx.m_length = static_cast<size_t>(n);
                    m_sendCtx.m_followedByRecv = true;
                    addTask(IOEventType::SEND, &m_sendCtx);
                }
            }
            m_recvCtx.m_buffer = m_ioBuf.data();
            m_recvCtx.m_length = m_ioBuf.size();
            addTask(IOEventType::RECV, &m_recvCtx);
            return;
        }

        case SslIOResult::ZeroReturn:
            m_result = {};
            m_resultSet = true;
            return;

        default:
            m_result = {};
            m_resultSet = true;
            return;
    }
}

std::expected<void, SslError> SslShutdownAwaitable::await_resume()
{
    onCompleted();
    return std::move(m_result);
}

// --- ShutdownRecvCtx ---

#ifdef USE_IOURING
bool SslShutdownAwaitable::ShutdownRecvCtx::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    auto result = io::handleRecv(cqe, m_buffer);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        m_owner->m_result = {};
        m_owner->m_resultSet = true;
        return true;
    }

    auto& bytes = result.value();
    m_owner->m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    m_owner->tryShutdown();
    return true;
}
#else
bool SslShutdownAwaitable::ShutdownRecvCtx::handleComplete(GHandle handle)
{
    bool fedAny = false;
    while (true) {
        auto result = io::handleRecv(handle, m_buffer, m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            break;
        }
        if (!result) {
            m_owner->m_result = {};
            m_owner->m_resultSet = true;
            return true;
        }

        auto& bytes = result.value();
        m_owner->m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        fedAny = true;
    }

    if (fedAny) {
        m_owner->tryShutdown();
        return true;
    }
    return false;
}
#endif

// --- ShutdownSendCtx ---

#ifdef USE_IOURING
bool SslShutdownAwaitable::ShutdownSendCtx::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    auto result = io::handleSend(cqe);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        m_owner->m_result = {};
        m_owner->m_resultSet = true;
        return true;
    }

    if (!m_followedByRecv && !m_owner->m_resultSet) {
        m_owner->tryShutdown();
    }
    return true;
}
#else
bool SslShutdownAwaitable::ShutdownSendCtx::handleComplete(GHandle handle)
{
    while (m_length > 0) {
        auto result = io::handleSend(handle, m_buffer, m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            return false;
        }
        if (!result) {
            m_owner->m_result = {};
            m_owner->m_resultSet = true;
            return true;
        }

        size_t sent = result.value();
        if (sent == 0) {
            return false;
        }
        m_buffer += sent;
        m_length -= sent;
    }

    if (!m_followedByRecv && !m_owner->m_resultSet) {
        m_owner->tryShutdown();
    }
    return true;
}
#endif

} // namespace galay::ssl
