#ifndef GALAY_SSL_AWAITABLE_H
#define GALAY_SSL_AWAITABLE_H

#include "galay-ssl/common/Error.h"
#include "galay-ssl/ssl/SslEngine.h"
#include <galay-kernel/kernel/IOScheduler.hpp>
#include <galay-kernel/kernel/Awaitable.h>
#include <galay-kernel/kernel/Waker.h>
#include <galay-kernel/kernel/Timeout.hpp>
#include <galay-kernel/common/Bytes.h>
#include <coroutine>
#include <expected>

namespace galay::ssl
{

using namespace galay::kernel;

/**
 * @brief SSL 握手可等待对象
 */
struct SslHandshakeAwaitable : public RecvNotifyAwaitable {
    SslHandshakeAwaitable(IOController* controller, SslEngine* engine)
        : RecvNotifyAwaitable(controller), m_engine(engine), m_resultSet(false),
          m_registeredType(IOEventType::INVALID) {}

    bool await_suspend(std::coroutine_handle<> handle);
    std::expected<void, SslError> await_resume();

    SslEngine* m_engine;
    std::expected<void, SslError> m_result;
    bool m_resultSet;
    IOEventType m_registeredType;
};

/**
 * @brief SSL 读取可等待对象
 */
struct SslRecvAwaitable : public RecvNotifyAwaitable {
    SslRecvAwaitable(IOController* controller, SslEngine* engine,
                     char* buffer, size_t length)
        : RecvNotifyAwaitable(controller), m_engine(engine),
          m_buffer(buffer), m_length(length), m_resultSet(false),
          m_registeredType(IOEventType::INVALID) {}

    bool await_suspend(std::coroutine_handle<> handle);
    std::expected<Bytes, SslError> await_resume();

    SslEngine* m_engine;
    char* m_buffer;
    size_t m_length;
    std::expected<Bytes, SslError> m_result;
    bool m_resultSet;
    IOEventType m_registeredType;
};

/**
 * @brief SSL 写入可等待对象
 */
struct SslSendAwaitable : public SendNotifyAwaitable {
    SslSendAwaitable(IOController* controller, SslEngine* engine,
                     const char* buffer, size_t length)
        : SendNotifyAwaitable(controller), m_engine(engine),
          m_buffer(buffer), m_length(length), m_resultSet(false),
          m_registeredType(IOEventType::INVALID) {}

    bool await_suspend(std::coroutine_handle<> handle);
    std::expected<size_t, SslError> await_resume();

    SslEngine* m_engine;
    const char* m_buffer;
    size_t m_length;
    std::expected<size_t, SslError> m_result;
    bool m_resultSet;
    IOEventType m_registeredType;
};

/**
 * @brief SSL 关闭可等待对象
 */
struct SslShutdownAwaitable : public RecvNotifyAwaitable {
    SslShutdownAwaitable(IOController* controller, SslEngine* engine)
        : RecvNotifyAwaitable(controller), m_engine(engine), m_resultSet(false),
          m_registeredType(IOEventType::INVALID) {}

    bool await_suspend(std::coroutine_handle<> handle);
    std::expected<void, SslError> await_resume();

    SslEngine* m_engine;
    std::expected<void, SslError> m_result;
    bool m_resultSet;
    IOEventType m_registeredType;
};

} // namespace galay::ssl

#endif // GALAY_SSL_AWAITABLE_H
