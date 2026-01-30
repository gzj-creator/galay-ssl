#include "Awaitable.h"
#include <cerrno>

namespace galay::ssl
{

// ==================== SslHandshakeAwaitable ====================

bool SslHandshakeAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);

    // 尝试执行握手
    SslIOResult result = m_engine->doHandshake();

    switch (result) {
        case SslIOResult::Success:
            m_result = {};
            m_resultSet = true;
            return false;  // 立即完成，不挂起

        case SslIOResult::WantRead: {
            // 需要等待可读
            m_registeredType = IOEventType::RECV_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addRecvNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::WantWrite: {
            // 需要等待可写
            m_registeredType = IOEventType::SEND_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addSendNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::ZeroReturn:
            m_result = std::unexpected(SslError(SslErrorCode::kPeerClosed));
            m_resultSet = true;
            return false;

        case SslIOResult::Syscall:
        case SslIOResult::Error:
        default:
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kHandshakeFailed));
            m_resultSet = true;
            return false;
    }
}

std::expected<void, SslError> SslHandshakeAwaitable::await_resume()
{
    // 清理已注册的事件
    m_controller->removeAwaitable(m_controller->m_type);

    // 如果结果还没有准备好，重新尝试握手
    if (!m_resultSet) {
        SslIOResult result = m_engine->doHandshake();

        switch (result) {
            case SslIOResult::Success:
                m_result = {};
                m_resultSet = true;
                break;

            case SslIOResult::WantRead:
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeWantRead));
                m_resultSet = true;
                break;

            case SslIOResult::WantWrite:
                m_result = std::unexpected(SslError(SslErrorCode::kHandshakeWantWrite));
                m_resultSet = true;
                break;

            case SslIOResult::ZeroReturn:
                m_result = std::unexpected(SslError(SslErrorCode::kPeerClosed));
                m_resultSet = true;
                break;

            default:
                m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kHandshakeFailed));
                m_resultSet = true;
                break;
        }
    }

    return std::move(m_result);
}

// ==================== SslRecvAwaitable ====================

bool SslRecvAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);

    // 先检查 SSL 缓冲区中是否有待读数据
    if (m_engine->pending() > 0) {
        size_t bytesRead = 0;
        SslIOResult result = m_engine->read(m_buffer, m_length, bytesRead);
        if (result == SslIOResult::Success) {
            m_result = Bytes(m_buffer, bytesRead);
            m_resultSet = true;
            return false;
        }
    }

    // 尝试读取
    size_t bytesRead = 0;
    SslIOResult result = m_engine->read(m_buffer, m_length, bytesRead);

    switch (result) {
        case SslIOResult::Success:
            m_result = Bytes(m_buffer, bytesRead);
            m_resultSet = true;
            return false;

        case SslIOResult::WantRead: {
            m_registeredType = IOEventType::RECV_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kReadFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addRecvNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kReadFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::WantWrite: {
            // SSL 重协商时可能需要写
            m_registeredType = IOEventType::SEND_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kReadFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addSendNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kReadFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::ZeroReturn:
            m_result = Bytes();
            m_resultSet = true;
            return false;

        case SslIOResult::Syscall:
        case SslIOResult::Error:
        default:
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
            m_resultSet = true;
            return false;
    }
}

std::expected<Bytes, SslError> SslRecvAwaitable::await_resume()
{
    // 清理已注册的事件
    m_controller->removeAwaitable(m_controller->m_type);

    // 如果结果还没有准备好，重新尝试接收
    if (!m_resultSet) {
        // 先检查SSL缓冲区
        if (m_engine->pending() > 0) {
            size_t bytesRead = 0;
            SslIOResult result = m_engine->read(m_buffer, m_length, bytesRead);
            if (result == SslIOResult::Success) {
                m_result = Bytes(m_buffer, bytesRead);
                m_resultSet = true;
            } else {
                m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
                m_resultSet = true;
            }
        } else {
            size_t bytesRead = 0;
            SslIOResult result = m_engine->read(m_buffer, m_length, bytesRead);

            switch (result) {
                case SslIOResult::Success:
                    m_result = Bytes(m_buffer, bytesRead);
                    m_resultSet = true;
                    break;

                case SslIOResult::ZeroReturn:
                    m_result = Bytes();
                    m_resultSet = true;
                    break;

                default:
                    m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kReadFailed));
                    m_resultSet = true;
                    break;
            }
        }
    }

    return std::move(m_result);
}

// ==================== SslSendAwaitable ====================

bool SslSendAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);

    // 尝试写入
    size_t bytesWritten = 0;
    SslIOResult result = m_engine->write(m_buffer, m_length, bytesWritten);

    switch (result) {
        case SslIOResult::Success:
            m_result = bytesWritten;
            m_resultSet = true;
            return false;

        case SslIOResult::WantWrite: {
            m_registeredType = IOEventType::SEND_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kWriteFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addSendNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kWriteFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::WantRead: {
            // SSL需要读取数据才能继续发送（可能是重协商）
            m_registeredType = IOEventType::RECV_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kWriteFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addRecvNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kWriteFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::ZeroReturn:
            m_result = std::unexpected(SslError(SslErrorCode::kPeerClosed));
            m_resultSet = true;
            return false;

        case SslIOResult::Syscall:
        case SslIOResult::Error:
        default:
            m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kWriteFailed));
            m_resultSet = true;
            return false;
    }
}

std::expected<size_t, SslError> SslSendAwaitable::await_resume()
{
    // 清理已注册的事件
    m_controller->removeAwaitable(m_controller->m_type);

    // 如果结果还没有准备好，重新尝试发送
    if (!m_resultSet) {
        size_t bytesWritten = 0;
        SslIOResult result = m_engine->write(m_buffer, m_length, bytesWritten);

        switch (result) {
            case SslIOResult::Success:
                m_result = bytesWritten;
                m_resultSet = true;
                break;

            default:
                m_result = std::unexpected(SslError::fromOpenSSL(SslErrorCode::kWriteFailed));
                m_resultSet = true;
                break;
        }
    }

    return std::move(m_result);
}

// ==================== SslShutdownAwaitable ====================

bool SslShutdownAwaitable::await_suspend(std::coroutine_handle<> handle)
{
    m_waker = Waker(handle);

    // 尝试关闭
    SslIOResult result = m_engine->shutdown();

    switch (result) {
        case SslIOResult::Success:
            m_result = {};
            m_resultSet = true;
            return false;

        case SslIOResult::WantRead: {
            m_registeredType = IOEventType::RECV_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kShutdownFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addRecvNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kShutdownFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::WantWrite: {
            m_registeredType = IOEventType::SEND_NOTIFY;
            m_controller->fillAwaitable(m_registeredType, this);
            auto scheduler = m_waker.getScheduler();
            if (scheduler->type() != kIOScheduler) {
                m_result = std::unexpected(SslError(SslErrorCode::kShutdownFailed, EINVAL));
                m_resultSet = true;
                return false;
            }
            auto io_scheduler = static_cast<IOScheduler*>(scheduler);
            if (io_scheduler->addSendNotify(m_controller) < 0) {
                m_result = std::unexpected(SslError(SslErrorCode::kShutdownFailed, errno));
                m_resultSet = true;
                return false;
            }
            return true;
        }

        case SslIOResult::ZeroReturn:
            m_result = {};
            m_resultSet = true;
            return false;

        case SslIOResult::Syscall:
        case SslIOResult::Error:
        default:
            m_result = {};
            m_resultSet = true;
            return false;
    }
}

std::expected<void, SslError> SslShutdownAwaitable::await_resume()
{
    // 清理已注册的事件
    m_controller->removeAwaitable(m_controller->m_type);
    return std::move(m_result);
}

} // namespace galay::ssl
