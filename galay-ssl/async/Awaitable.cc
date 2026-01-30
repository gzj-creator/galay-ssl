#include "Awaitable.h"
#include <cerrno>

namespace galay::ssl
{

// ==================== 辅助函数 ====================

namespace {

/**
 * @brief 获取 IOScheduler 指针
 * @return 成功返回 IOScheduler*，失败返回 nullptr
 */
inline IOScheduler* getIOScheduler(Waker& waker)
{
    auto scheduler = waker.getScheduler();
    if (scheduler->type() != kIOScheduler) {
        return nullptr;
    }
    return static_cast<IOScheduler*>(scheduler);
}

/**
 * @brief 注册读事件
 * @return 成功返回 true
 */
inline bool registerRecvNotify(IOController* controller, IOEventType& registeredType,
                               void* awaitable, Waker& waker)
{
    registeredType = IOEventType::RECV_NOTIFY;
    controller->fillAwaitable(registeredType, awaitable);
    auto io_scheduler = getIOScheduler(waker);
    if (!io_scheduler) {
        return false;
    }
    return io_scheduler->addRecvNotify(controller) >= 0;
}

/**
 * @brief 注册写事件
 * @return 成功返回 true
 */
inline bool registerSendNotify(IOController* controller, IOEventType& registeredType,
                               void* awaitable, Waker& waker)
{
    registeredType = IOEventType::SEND_NOTIFY;
    controller->fillAwaitable(registeredType, awaitable);
    auto io_scheduler = getIOScheduler(waker);
    if (!io_scheduler) {
        return false;
    }
    return io_scheduler->addSendNotify(controller) >= 0;
}

} // anonymous namespace

// ==================== SslHandshakeAwaitable ====================

bool SslHandshakeAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);
    SslIOResult result = m_engine->doHandshake();

    switch (result) {
        case SslIOResult::Success:
            m_result = {};
            m_resultSet = true;
            return false;

        case SslIOResult::WantRead:
            if (registerRecvNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, errno));
            m_resultSet = true;
            return false;

        case SslIOResult::WantWrite:
            if (registerSendNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, errno));
            m_resultSet = true;
            return false;

        case SslIOResult::ZeroReturn:
            m_result = std::unexpected(SslError(SslErrorCode::kPeerClosed));
            m_resultSet = true;
            return false;

        default:
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kHandshakeFailed));
            m_resultSet = true;
            return false;
    }
}

std::expected<void, SslError> SslHandshakeAwaitable::await_resume()
{
    m_controller->removeAwaitable(m_controller->m_type);

    if (!m_resultSet) {
        SslIOResult result = m_engine->doHandshake();

        switch (result) {
            case SslIOResult::Success:
                m_result = {};
                break;
            case SslIOResult::WantRead:
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeWantRead));
                break;
            case SslIOResult::WantWrite:
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeWantWrite));
                break;
            case SslIOResult::ZeroReturn:
                m_result = std::unexpected(SslError(SslErrorCode::kPeerClosed));
                break;
            default:
                m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kHandshakeFailed));
                break;
        }
        m_resultSet = true;
    }

    return std::move(m_result);
}

// ==================== SslRecvAwaitable ====================

bool SslRecvAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);

    // 尝试读取（SSL 内部可能有缓冲数据）
    size_t bytesRead = 0;
    SslIOResult result = m_engine->read(m_buffer, m_length, bytesRead);

    switch (result) {
        case SslIOResult::Success:
            m_result = Bytes(m_buffer, bytesRead);
            m_resultSet = true;
            return false;

        case SslIOResult::WantRead:
            if (registerRecvNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kReadFailed, errno));
            m_resultSet = true;
            return false;

        case SslIOResult::WantWrite:
            // SSL 重协商时可能需要写
            if (registerSendNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kReadFailed, errno));
            m_resultSet = true;
            return false;

        case SslIOResult::ZeroReturn:
            m_result = Bytes();
            m_resultSet = true;
            return false;

        default:
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
            m_resultSet = true;
            return false;
    }
}

std::expected<Bytes, SslError> SslRecvAwaitable::await_resume()
{
    m_controller->removeAwaitable(m_controller->m_type);

    if (!m_resultSet) {
        size_t bytesRead = 0;
        SslIOResult result = m_engine->read(m_buffer, m_length, bytesRead);

        switch (result) {
            case SslIOResult::Success:
                m_result = Bytes(m_buffer, bytesRead);
                break;
            case SslIOResult::ZeroReturn:
                m_result = Bytes();
                break;
            default:
                m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
                break;
        }
        m_resultSet = true;
    }

    return std::move(m_result);
}

// ==================== SslSendAwaitable ====================

bool SslSendAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);

    size_t bytesWritten = 0;
    SslIOResult result = m_engine->write(m_buffer, m_length, bytesWritten);

    switch (result) {
        case SslIOResult::Success:
            m_result = bytesWritten;
            m_resultSet = true;
            return false;

        case SslIOResult::WantWrite:
            if (registerSendNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kWriteFailed, errno));
            m_resultSet = true;
            return false;

        case SslIOResult::WantRead:
            // SSL 重协商时可能需要读
            if (registerRecvNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kWriteFailed, errno));
            m_resultSet = true;
            return false;

        case SslIOResult::ZeroReturn:
            m_result = std::unexpected(SslError(SslErrorCode::kPeerClosed));
            m_resultSet = true;
            return false;

        default:
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kWriteFailed));
            m_resultSet = true;
            return false;
    }
}

std::expected<size_t, SslError> SslSendAwaitable::await_resume()
{
    m_controller->removeAwaitable(m_controller->m_type);

    if (!m_resultSet) {
        size_t bytesWritten = 0;
        SslIOResult result = m_engine->write(m_buffer, m_length, bytesWritten);

        if (result == SslIOResult::Success) {
            m_result = bytesWritten;
        } else {
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kWriteFailed));
        }
        m_resultSet = true;
    }

    return std::move(m_result);
}

// ==================== SslShutdownAwaitable ====================

bool SslShutdownAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);
    SslIOResult result = m_engine->shutdown();

    switch (result) {
        case SslIOResult::Success:
        case SslIOResult::ZeroReturn:
            m_result = {};
            m_resultSet = true;
            return false;

        case SslIOResult::WantRead:
            if (registerRecvNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kShutdownFailed, errno));
            m_resultSet = true;
            return false;

        case SslIOResult::WantWrite:
            if (registerSendNotify(m_controller, m_registeredType, this, m_waker)) {
                return true;
            }
            m_result = std::unexpected(SslError(SslErrorCode::kShutdownFailed, errno));
            m_resultSet = true;
            return false;

        default:
            // shutdown 失败通常不是致命错误，返回成功
            m_result = {};
            m_resultSet = true;
            return false;
    }
}

std::expected<void, SslError> SslShutdownAwaitable::await_resume()
{
    m_controller->removeAwaitable(m_controller->m_type);
    return std::move(m_result);
}

} // namespace galay::ssl
