#include "Awaitable.h"
#include <cerrno>
#include <algorithm>
#include <limits>
#include <string_view>
#include <sys/event.h>
#include <unistd.h>

namespace galay::ssl
{

static constexpr size_t kCipherBufSize = 16384;
static constexpr size_t kMaxDrainBytes = 64 * 1024;

static bool ensureBufferSize(std::vector<char>& buffer, size_t required)
{
    if (required == 0 || required <= buffer.size()) {
        return true;
    }

    size_t newSize = buffer.size();
    if (newSize < kCipherBufSize) {
        newSize = kCipherBufSize;
    }

    while (newSize < required) {
        if (newSize > std::numeric_limits<size_t>::max() / 2) {
            newSize = required;
            break;
        }
        newSize *= 2;
    }

    if (newSize < required) {
        return false;
    }

    buffer.resize(newSize);
    return true;
}

static size_t drainChunkSize(size_t pending)
{
    if (pending == 0) {
        return kCipherBufSize;
    }
    return std::max(kCipherBufSize, std::min(pending, kMaxDrainBytes));
}

// ==================== SslRecvAwaitable ====================

SslRecvAwaitable::SslRecvAwaitable(IOController* controller, SslEngine* engine,
                                   char* buffer, size_t length,
                                   std::vector<char>* cipherBuffer)
    : CustomAwaitable(controller)
    , m_engine(engine)
    , m_plainBuffer(buffer)
    , m_plainLength(length)
    , m_cipherBuffer(cipherBuffer ? cipherBuffer : &m_cipherBufferOwned)
    , m_cipherBufferOwned()
    , m_recvCtx(nullptr, 0, this)
    , m_sendCtx(this)
{
    if (m_cipherBuffer->size() < kCipherBufSize) {
        m_cipherBuffer->resize(kCipherBufSize);
    }
    m_tasks.reserve(4);
    resetTaskQueue();
}

SslRecvAwaitable::SslRecvAwaitable(SslRecvAwaitable&& other) noexcept
    : CustomAwaitable(other.m_controller)
    , m_engine(other.m_engine)
    , m_plainBuffer(other.m_plainBuffer)
    , m_plainLength(other.m_plainLength)
    , m_cipherBuffer(nullptr)
    , m_cipherBufferOwned(std::move(other.m_cipherBufferOwned))
    , m_sslResult(std::move(other.m_sslResult))
    , m_sslResultSet(other.m_sslResultSet)
    , m_recvCtx(nullptr, 0, this)
    , m_sendCtx(this)
{
    if (other.m_cipherBuffer == &other.m_cipherBufferOwned) {
        m_cipherBuffer = &m_cipherBufferOwned;
    } else {
        m_cipherBuffer = other.m_cipherBuffer;
    }
    m_tasks.reserve(4);
    resetTaskQueue();
}

SslRecvAwaitable& SslRecvAwaitable::operator=(SslRecvAwaitable&& other) noexcept
{
    if (this == &other) {
        return *this;
    }

    m_controller = other.m_controller;
    m_waker = Waker();
    m_engine = other.m_engine;
    m_plainBuffer = other.m_plainBuffer;
    m_plainLength = other.m_plainLength;
    m_cipherBufferOwned = std::move(other.m_cipherBufferOwned);
    if (other.m_cipherBuffer == &other.m_cipherBufferOwned) {
        m_cipherBuffer = &m_cipherBufferOwned;
    } else {
        m_cipherBuffer = other.m_cipherBuffer;
    }
    m_sslResult = std::move(other.m_sslResult);
    m_sslResultSet = other.m_sslResultSet;
    m_recvCtx.m_owner = this;
    m_sendCtx.m_owner = this;
    resetTaskQueue();
    return *this;
}

void SslRecvAwaitable::resetTaskQueue()
{
    syncRecvBuffer();
    m_sendCtx.m_buffer = nullptr;
    m_sendCtx.m_length = 0;
    m_tasks.clear();
    m_cursor = 0;
    if (!m_sslResultSet) {
        addTask(IOEventType::RECV, &m_recvCtx);
    }
}

void SslRecvAwaitable::syncRecvBuffer()
{
    m_recvCtx.m_buffer = m_cipherBuffer->data();
    m_recvCtx.m_length = m_cipherBuffer->size();
}

SslRecvAwaitable::ReadAction SslRecvAwaitable::drainPlaintext()
{
    size_t totalRead = 0;
    while (totalRead < m_plainLength) {
        size_t bytesRead = 0;
        SslIOResult sslRet = m_engine->read(m_plainBuffer + totalRead,
                                            m_plainLength - totalRead,
                                            bytesRead);

        if (sslRet == SslIOResult::Success && bytesRead > 0) {
            totalRead += bytesRead;
            continue;
        }

        if (sslRet == SslIOResult::WantRead) {
            break;
        }

        if (sslRet == SslIOResult::WantWrite) {
            if (totalRead > 0) {
                m_sslResult = Bytes::fromString(std::string_view(m_plainBuffer, totalRead));
                m_sslResultSet = true;
                return ReadAction::Completed;
            }
            return ReadAction::NeedSend;
        }

        if (sslRet == SslIOResult::ZeroReturn) {
            if (totalRead > 0) {
                m_sslResult = Bytes::fromString(std::string_view(m_plainBuffer, totalRead));
            } else {
                m_sslResult = Bytes();
            }
            m_sslResultSet = true;
            return ReadAction::Completed;
        }

        if (totalRead > 0) {
            m_sslResult = Bytes::fromString(std::string_view(m_plainBuffer, totalRead));
        } else {
            m_sslResult = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
        }
        m_sslResultSet = true;
        return ReadAction::Completed;
    }

    if (totalRead > 0) {
        m_sslResult = Bytes::fromString(std::string_view(m_plainBuffer, totalRead));
        m_sslResultSet = true;
        return ReadAction::Completed;
    }

    return ReadAction::NeedRecv;
}

SslRecvAwaitable::SendChunkState SslRecvAwaitable::prepareSendChunk()
{
    if (m_sendCtx.m_length > 0) {
        return SendChunkState::Ready;
    }

    size_t pending = m_engine->pendingEncryptedOutput();
    if (pending == 0) {
        return SendChunkState::Drained;
    }

    size_t desired = drainChunkSize(pending);
    if (!ensureBufferSize(*m_cipherBuffer, desired)) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
        m_sslResultSet = true;
        return SendChunkState::Failed;
    }

    syncRecvBuffer();

    size_t toRead = std::min(pending, m_cipherBuffer->size());
    int n = m_engine->extractEncryptedOutput(m_cipherBuffer->data(), toRead);
    if (n <= 0) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
        m_sslResultSet = true;
        return SendChunkState::Failed;
    }

    m_sendCtx.m_buffer = m_cipherBuffer->data();
    m_sendCtx.m_length = static_cast<size_t>(n);
    return SendChunkState::Ready;
}

bool SslRecvAwaitable::scheduleSendThenRecv()
{
    SendChunkState state = prepareSendChunk();
    if (state == SendChunkState::Failed) {
        return true;
    }
    if (state == SendChunkState::Drained) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
        m_sslResultSet = true;
        return true;
    }

    addTask(IOEventType::SEND, &m_sendCtx);
    addTask(IOEventType::RECV, &m_recvCtx);
    return true;
}

// --- RecvCtx ---

#ifdef USE_IOURING
bool SslRecvAwaitable::RecvCtx::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    (void)handle;
    if (cqe == nullptr) {
        auto preAction = m_owner->drainPlaintext();
        if (preAction == SslRecvAwaitable::ReadAction::Completed) {
            return true;
        }
        if (preAction == SslRecvAwaitable::ReadAction::NeedSend) {
            return m_owner->scheduleSendThenRecv();
        }
        return false;
    }

    auto result = io::handleRecv(cqe, m_buffer);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        if (IOError::contains(result.error().code(), kDisconnectError)) {
            m_owner->m_sslResult = Bytes();
        } else {
            m_owner->m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
        }
        m_owner->m_sslResultSet = true;
        return true;
    }

    auto& bytes = result.value();
    m_owner->m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    auto action = m_owner->drainPlaintext();
    if (action == SslRecvAwaitable::ReadAction::Completed) {
        return true;
    }
    if (action == SslRecvAwaitable::ReadAction::NeedSend) {
        return m_owner->scheduleSendThenRecv();
    }
    return false;
}
#else
bool SslRecvAwaitable::RecvCtx::handleComplete(GHandle handle)
{
    auto preAction = m_owner->drainPlaintext();
    if (preAction == SslRecvAwaitable::ReadAction::Completed) {
        return true;
    }
    if (preAction == SslRecvAwaitable::ReadAction::NeedSend) {
        return m_owner->scheduleSendThenRecv();
    }

    // ET 模式下尽量读到 EAGAIN，避免“吃掉边沿”导致卡住。
    while (true) {
        auto result = io::handleRecv(handle, m_buffer, m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            return false;
        }
        if (!result) {
            if (IOError::contains(result.error().code(), kDisconnectError)) {
                m_owner->m_sslResult = Bytes();
            } else {
                m_owner->m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
            }
            m_owner->m_sslResultSet = true;
            return true;
        }

        auto& bytes = result.value();
        m_owner->m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());

        auto action = m_owner->drainPlaintext();
        if (action == SslRecvAwaitable::ReadAction::Completed) {
            return true;
        }
        if (action == SslRecvAwaitable::ReadAction::NeedSend) {
            return m_owner->scheduleSendThenRecv();
        }
    }
}
#endif

// --- SendCtx ---

#ifdef USE_IOURING
bool SslRecvAwaitable::SendCtx::handleComplete(struct io_uring_cqe* cqe, GHandle handle)
{
    (void)handle;
    if (cqe == nullptr) {
        auto state = m_owner->prepareSendChunk();
        return state != SslRecvAwaitable::SendChunkState::Ready;
    }

    auto result = io::handleSend(cqe);
    if (!result && IOError::contains(result.error().code(), kNotReady)) {
        return false;
    }
    if (!result) {
        m_owner->m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
        m_owner->m_sslResultSet = true;
        return true;
    }

    size_t sent = result.value();
    if (sent == 0) {
        return false;
    }

    if (sent < m_length) {
        m_buffer += sent;
        m_length -= sent;
        return false;
    }

    m_buffer += m_length;
    m_length = 0;

    auto state = m_owner->prepareSendChunk();
    return state != SslRecvAwaitable::SendChunkState::Ready;
}
#else
bool SslRecvAwaitable::SendCtx::handleComplete(GHandle handle)
{
    while (true) {
        if (m_length == 0) {
            auto state = m_owner->prepareSendChunk();
            if (state == SslRecvAwaitable::SendChunkState::Ready) {
                // 继续发送新块
            } else {
                return true;
            }
        }

        auto result = io::handleSend(handle, m_buffer, m_length);
        if (!result && IOError::contains(result.error().code(), kNotReady)) {
            return false;
        }
        if (!result) {
            m_owner->m_sslResult = std::unexpected(SslError(SslErrorCode::kReadFailed, 0));
            m_owner->m_sslResultSet = true;
            return true;
        }

        size_t sent = result.value();
        if (sent == 0) {
            return false;
        }

        m_buffer += sent;
        m_length -= sent;
    }
}
#endif

bool SslRecvAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    if (drainPlaintext() == ReadAction::Completed) {
        return false;
    }

    return CustomAwaitable::await_suspend(handle);
}

std::expected<Bytes, SslError> SslRecvAwaitable::await_resume()
{
    onCompleted();

    if (m_sslResultSet) {
        return std::move(m_sslResult);
    }

    return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
}

// ==================== SslSendAwaitable ====================

SslSendAwaitable::SslSendAwaitable(IOController* controller, SslEngine* engine,
                                   const char* buffer, size_t length,
                                   std::vector<char>* cipherBuffer)
    : SendAwaitable(controller, nullptr, 0)
    , m_engine(engine)
    , m_plainBuffer(buffer)
    , m_plainLength(length)
    , m_cipherBuffer(cipherBuffer ? cipherBuffer : &m_cipherBufferOwned)
    , m_cipherBufferOwned()
{
    if (!ensureBufferSize(*m_cipherBuffer, kCipherBufSize)) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
        m_sslResultSet = true;
        return;
    }

    if (!fillNextSendChunk() && !m_sslResultSet) {
        m_sslResult = m_plainLength;
        m_sslResultSet = true;
    }
}

bool SslSendAwaitable::fillNextSendChunk()
{
    while (true) {
        if (SendIOContext::m_length > 0) {
            return true;
        }

        size_t pending = m_engine->pendingEncryptedOutput();
        if (pending > 0) {
            size_t desired = drainChunkSize(pending);
            if (!ensureBufferSize(*m_cipherBuffer, desired)) {
                m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
                m_sslResultSet = true;
                return false;
            }

            size_t toRead = std::min(pending, m_cipherBuffer->size());
            int n = m_engine->extractEncryptedOutput(m_cipherBuffer->data(), toRead);
            if (n <= 0) {
                m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
                m_sslResultSet = true;
                return false;
            }

            m_cipherLength = static_cast<size_t>(n);
            SendIOContext::m_buffer = m_cipherBuffer->data();
            SendIOContext::m_length = m_cipherLength;
            return true;
        }

        if (m_plainOffset >= m_plainLength) {
            m_cipherLength = 0;
            SendIOContext::m_buffer = nullptr;
            SendIOContext::m_length = 0;
            m_sslResult = m_plainLength;
            m_sslResultSet = true;
            return false;
        }

        size_t bytesWritten = 0;
        SslIOResult sslRet = m_engine->write(m_plainBuffer + m_plainOffset,
                                             m_plainLength - m_plainOffset,
                                             bytesWritten);
        if (sslRet == SslIOResult::Success && bytesWritten > 0) {
            m_plainOffset += bytesWritten;
            continue;
        }

        if ((sslRet == SslIOResult::WantRead || sslRet == SslIOResult::WantWrite) &&
            m_engine->pendingEncryptedOutput() > 0) {
            continue;
        }

        m_sslResult = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kWriteFailed));
        m_sslResultSet = true;
        SendIOContext::m_buffer = nullptr;
        SendIOContext::m_length = 0;
        return false;
    }
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

    size_t sent = result.value();
    if (sent == 0) {
        m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
        m_sslResultSet = true;
        return true;
    }

    if (sent < SendIOContext::m_length) {
        SendIOContext::m_buffer += sent;
        SendIOContext::m_length -= sent;
        return false;
    }

    SendIOContext::m_buffer += SendIOContext::m_length;
    SendIOContext::m_length = 0;

    if (fillNextSendChunk()) {
        return false;
    }

    return true;
}
#else
bool SslSendAwaitable::handleComplete(GHandle handle)
{
    // 同 recv：尽量在一次回调里把数据 send 到 EAGAIN，避免边沿触发场景卡住
    while (true) {
        while (SendIOContext::m_length > 0) {
            auto result = io::handleSend(handle, SendIOContext::m_buffer, SendIOContext::m_length);
            if (!result && IOError::contains(result.error().code(), kNotReady)) {
                return false;
            }
            if (!result) {
                m_sslResult = std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
                m_sslResultSet = true;
                return true;
            }

            size_t sent = result.value();
            if (sent == 0) {
                return false;
            }
            SendIOContext::m_buffer += sent;
            SendIOContext::m_length -= sent;
        }

        if (m_sslResultSet) {
            return true;
        }

        if (!fillNextSendChunk()) {
            if (m_sslResultSet) {
                return true;
            }
            m_sslResult = m_plainLength;
            m_sslResultSet = true;
            return true;
        }
    }
}
#endif

bool SslSendAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    if (m_sslResultSet) {
        return false;
    }

    return SendAwaitable::await_suspend(handle);
}

std::expected<size_t, SslError> SslSendAwaitable::await_resume()
{
    if (m_sslResultSet) {
        m_controller->removeAwaitable(IOEventType::SEND);
        return std::move(m_sslResult);
    }

    auto result = SendAwaitable::await_resume();
    m_controller->removeAwaitable(IOEventType::SEND);

    if (!result) {
        return std::unexpected(SslError(SslErrorCode::kWriteFailed, 0));
    }

    if (!m_sslResultSet) {
        m_sslResult = m_plainLength;
        m_sslResultSet = true;
    }

    return std::move(m_sslResult);
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

    switch (ret) {
        case SslIOResult::Success: {
            // 握手成功，但可能有待发送的加密数据（如 TLS 1.3 NewSessionTicket）
            size_t pending = m_engine->pendingEncryptedOutput();
            if (pending > 0) {
                if (!ensureBufferSize(m_ioBuf, pending)) {
                    m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
                    m_resultSet = true;
                    return;
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
            if (!ensureBufferSize(m_ioBuf, pending)) {
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
                m_resultSet = true;
                return;
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
                if (!ensureBufferSize(m_ioBuf, pending)) {
                    m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
                    m_resultSet = true;
                    return;
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
            break;
        }
        if (!result) {
            m_owner->m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
            m_owner->m_resultSet = true;
            return true;
        }

        auto& bytes = result.value();
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
            return false;
        }
        if (!result) {
            m_owner->m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, 0));
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
            if (!ensureBufferSize(m_ioBuf, pending)) {
                m_result = {};
                m_resultSet = true;
                return;
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
                if (!ensureBufferSize(m_ioBuf, pending)) {
                    m_result = {};
                    m_resultSet = true;
                    return;
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
