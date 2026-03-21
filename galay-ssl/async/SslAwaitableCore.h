#ifndef GALAY_SSL_AWAITABLE_CORE_H
#define GALAY_SSL_AWAITABLE_CORE_H

#include "galay-ssl/common/Error.h"
#include <galay-kernel/common/Bytes.h>
#include <galay-kernel/kernel/Awaitable.h>
#include <galay-kernel/kernel/Timeout.hpp>
#include <concepts>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace galay::ssl
{

using namespace galay::kernel;

class SslSocket;

enum class SslMachineSignal : uint8_t {
    kContinue,
    kHandshake,
    kRecv,
    kSend,
    kShutdown,
    kComplete,
    kFail,
};

template <typename ResultT>
struct SslMachineAction {
    SslMachineSignal signal = SslMachineSignal::kContinue;
    char* read_buffer = nullptr;
    size_t read_length = 0;
    const char* write_buffer = nullptr;
    size_t write_length = 0;
    std::optional<ResultT> result;
    std::optional<SslError> error;

    static SslMachineAction continue_()
    {
        return {};
    }

    static SslMachineAction handshake()
    {
        SslMachineAction action;
        action.signal = SslMachineSignal::kHandshake;
        return action;
    }

    static SslMachineAction recv(char* buffer, size_t length)
    {
        SslMachineAction action;
        action.signal = SslMachineSignal::kRecv;
        action.read_buffer = buffer;
        action.read_length = length;
        return action;
    }

    static SslMachineAction send(const char* buffer, size_t length)
    {
        SslMachineAction action;
        action.signal = SslMachineSignal::kSend;
        action.write_buffer = buffer;
        action.write_length = length;
        return action;
    }

    static SslMachineAction shutdown()
    {
        SslMachineAction action;
        action.signal = SslMachineSignal::kShutdown;
        return action;
    }

    static SslMachineAction complete(ResultT value)
    {
        SslMachineAction action;
        action.signal = SslMachineSignal::kComplete;
        action.result = std::move(value);
        return action;
    }

    static SslMachineAction fail(SslError error)
    {
        SslMachineAction action;
        action.signal = SslMachineSignal::kFail;
        action.error = std::move(error);
        return action;
    }
};

template <typename MachineT>
concept SslAwaitableStateMachine =
    requires(MachineT& machine,
             std::expected<void, SslError> handshake_result,
             std::expected<Bytes, SslError> recv_result,
             std::expected<size_t, SslError> send_result,
             std::expected<void, SslError> shutdown_result) {
        typename MachineT::result_type;
        { machine.advance() } -> std::same_as<SslMachineAction<typename MachineT::result_type>>;
        { machine.onHandshake(std::move(handshake_result)) } -> std::same_as<void>;
        { machine.onRecv(std::move(recv_result)) } -> std::same_as<void>;
        { machine.onSend(std::move(send_result)) } -> std::same_as<void>;
        { machine.onShutdown(std::move(shutdown_result)) } -> std::same_as<void>;
    };

struct SslHandshakeContext {
    std::expected<void, SslError> m_result{};
};

struct SslRecvContext {
    SslRecvContext(char* buffer = nullptr, size_t length = 0)
        : m_buffer(buffer)
        , m_length(length) {}

    char* m_buffer = nullptr;
    size_t m_length = 0;
    std::expected<Bytes, SslError> m_result{};
};

struct SslSendContext {
    SslSendContext(const char* buffer = nullptr, size_t length = 0)
        : m_buffer(buffer)
        , m_length(length) {}

    const char* m_buffer = nullptr;
    size_t m_length = 0;
    std::expected<size_t, SslError> m_result{};
};

struct SslShutdownContext {
    std::expected<void, SslError> m_result{};
};

template <typename ResultT>
class SslBuilderOutcome
{
public:
    template <typename ValueT>
    void complete(ValueT&& value)
    {
        m_result = std::forward<ValueT>(value);
        m_result_set = true;
        m_queue_used = false;
    }

    void clear()
    {
        m_result.reset();
        m_result_set = false;
        m_queue_used = false;
    }

    void markQueueUsed()
    {
        m_queue_used = true;
    }

    bool hasResultValue() const
    {
        return m_result_set && m_result.has_value();
    }

    std::optional<ResultT> takeResultValue()
    {
        m_result_set = false;
        auto result = std::move(m_result);
        m_result.reset();
        return result;
    }

    bool queueUsed() const
    {
        return m_queue_used;
    }

    void reset()
    {
        clear();
    }

private:
    std::optional<ResultT> m_result;
    bool m_result_set = false;
    bool m_queue_used = false;
};

template <typename ResultT, size_t InlineN = 4>
class SslBuilderOps
{
public:
    explicit SslBuilderOps(SslBuilderOutcome<ResultT>& owner)
        : m_owner(owner) {}

    template <typename StepT>
    StepT& queue(StepT& step)
    {
        m_owner.markQueueUsed();
        return step;
    }

    template <typename... StepTs>
    void queueMany(StepTs&... steps)
    {
        (queue(steps), ...);
    }

    void clear()
    {
        m_owner.clear();
    }

    template <typename ValueT>
    void complete(ValueT&& value)
    {
        m_owner.complete(std::forward<ValueT>(value));
    }

private:
    SslBuilderOutcome<ResultT>& m_owner;
};

namespace detail {

template <typename T>
struct is_expected : std::false_type {};

template <typename T, typename E>
struct is_expected<std::expected<T, E>> : std::true_type {};

template <typename ResultT>
constexpr bool is_expected_v = is_expected<std::remove_cvref_t<ResultT>>::value;

template <typename ResultT>
struct expected_traits;

template <typename T, typename E>
struct expected_traits<std::expected<T, E>> {
    using value_type = T;
    using error_type = E;
};

} // namespace detail

class SslOperationDriver
{
public:
    enum class WaitKind : uint8_t {
        kNone,
        kRead,
        kWrite,
    };

    struct WaitAction {
        WaitKind kind = WaitKind::kNone;
        IOContextBase* context = nullptr;
    };

    explicit SslOperationDriver(SslSocket* socket);

    void startHandshake();
    void startRecv(char* buffer, size_t length);
    void startSend(const char* buffer, size_t length);
    void startShutdown();

    WaitAction poll();
    void onRead(std::expected<size_t, IOError> result);
    void onWrite(std::expected<size_t, IOError> result);

    bool completed() const;

    std::expected<void, SslError> takeHandshakeResult();
    std::expected<Bytes, SslError> takeRecvResult();
    std::expected<size_t, SslError> takeSendResult();
    std::expected<void, SslError> takeShutdownResult();

    RecvIOContext& recvContext() { return m_recv_context; }
    SendIOContext& sendContext() { return m_send_context; }

private:
    enum class OperationKind : uint8_t {
        kNone,
        kHandshake,
        kRecv,
        kSend,
        kShutdown,
    };

    enum class RecvPollAction : uint8_t {
        kNeedRecv,
        kNeedSend,
        kCompleted,
    };

    void resetContexts();
    void resetHandshakeState();
    void resetRecvState();
    void resetSendState();
    void resetShutdownState();
    void clearOperation();

    WaitAction pollHandshake();
    WaitAction pollRecv();
    WaitAction pollSend();
    WaitAction pollShutdown();

    void onHandshakeRead(std::expected<size_t, IOError> result);
    void onHandshakeWrite(std::expected<size_t, IOError> result);
    void onRecvRead(std::expected<size_t, IOError> result);
    void onRecvWrite(std::expected<size_t, IOError> result);
    void onSendWrite(std::expected<size_t, IOError> result);
    void onShutdownRead(std::expected<size_t, IOError> result);
    void onShutdownWrite(std::expected<size_t, IOError> result);

    bool prepareReadBuffer(std::vector<char>& buffer);
    bool prepareWriteFromPending(std::vector<char>& buffer, SslErrorCode error_code);
    bool prepareRecvSendChunk();
    bool fillSendChunk();
    RecvPollAction drainRecvPlaintext();

    void setHandshakeFailure(SslError error);
    void setRecvFailure(SslError error);
    void setSendFailure(SslError error);
    void setShutdownSuccess();
    void clearTransientBuffers();

    OperationKind m_operation = OperationKind::kNone;
    SslSocket* m_socket = nullptr;
    RecvIOContext m_recv_context;
    SendIOContext m_send_context;

    struct HandshakeState {
        bool result_set = false;
        std::expected<void, SslError> result{};
        bool flush_success = false;
        bool wait_read_after_write = false;
        bool read_pending = false;
    } m_handshake;

    struct RecvState {
        char* plain_buffer = nullptr;
        size_t plain_length = 0;
        bool result_set = false;
        std::expected<Bytes, SslError> result{};
    } m_recv;

    struct SendState {
        const char* plain_buffer = nullptr;
        size_t plain_length = 0;
        size_t plain_offset = 0;
        bool result_set = false;
        std::expected<size_t, SslError> result{};
    } m_send;

    struct ShutdownState {
        bool result_set = false;
        std::expected<void, SslError> result{};
        bool wait_read_after_write = false;
        bool read_pending = false;
    } m_shutdown;
    std::vector<char> m_handshake_buffer;
    std::vector<char> m_shutdown_buffer;
    std::vector<char> m_recv_cipher_buffer;
    std::vector<char> m_send_cipher_buffer;
};

template <SslAwaitableStateMachine MachineT>
class SslStateMachineAwaitable
    : public SequenceAwaitableBase
    , public TimeoutSupport<SslStateMachineAwaitable<MachineT>> {
public:
    using result_type = typename MachineT::result_type;

    SslStateMachineAwaitable(IOController* controller, SslSocket* socket, MachineT machine)
        : SequenceAwaitableBase(controller)
        , m_socket(socket)
        , m_machine(std::move(machine))
        , m_driver(socket) {}

    bool await_ready()
    {
        return m_result_set || m_error.has_value() || SequenceAwaitableBase::m_error.has_value();
    }

    template <typename Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle)
    {
        if (!m_context_bound) {
            galay::kernel::detail::bindAwaitContextIfSupported(
                m_machine,
                galay::kernel::detail::makeAwaitContext(handle));
            m_context_bound = true;
        }
        return SequenceAwaitableBase::await_suspend(handle);
    }

    auto await_resume() -> result_type
    {
        onCompleted();
        if (m_result_set) {
            return std::move(*m_result);
        }
        if (m_error.has_value()) {
            if constexpr (detail::is_expected_v<result_type>) {
                using ErrorT = typename detail::expected_traits<result_type>::error_type;
                if constexpr (std::is_constructible_v<ErrorT, SslError>) {
                    return std::unexpected(ErrorT(*m_error));
                }
            }
        }
        if (SequenceAwaitableBase::m_error.has_value()) {
            // Sequence registration can fail immediately before the SSL machine
            // produces a driver-level SslError. Bridge that base error instead of aborting.
            if constexpr (detail::is_expected_v<result_type>) {
                using ErrorT = typename detail::expected_traits<result_type>::error_type;
                if constexpr (std::is_constructible_v<ErrorT, SslError>) {
                    return std::unexpected(ErrorT(bridgeSequenceError(*SequenceAwaitableBase::m_error)));
                }
            }
        }
        std::abort();
    }

    IOTask* front() override
    {
        return m_has_active_task ? &m_active_task : nullptr;
    }

    const IOTask* front() const override
    {
        return m_has_active_task ? &m_active_task : nullptr;
    }

    void popFront() override
    {
        clearActiveTask();
    }

    bool empty() const override
    {
        return !m_has_active_task;
    }

    void markTimeout()
    {
        setFailure(SslError(SslErrorCode::kTimeout));
        clearActiveTask();
    }

#ifdef USE_IOURING
    SequenceProgress prepareForSubmit() override
    {
        return pump();
    }

    SequenceProgress onActiveEvent(struct io_uring_cqe* cqe, GHandle handle) override
    {
        if (!m_has_active_task) {
            return pump();
        }
        if (m_active_kind == ActiveKind::kRead) {
            if (!m_driver.recvContext().handleComplete(cqe, handle)) {
                return SequenceProgress::kNeedWait;
            }
            auto io_result = std::move(m_driver.recvContext().m_result);
            clearActiveTask();
            m_driver.onRead(std::move(io_result));
            return pump();
        }
        if (m_active_kind == ActiveKind::kWrite) {
            if (!m_driver.sendContext().handleComplete(cqe, handle)) {
                return SequenceProgress::kNeedWait;
            }
            auto io_result = std::move(m_driver.sendContext().m_result);
            clearActiveTask();
            m_driver.onWrite(std::move(io_result));
            return pump();
        }
        setFailure(SslError(SslErrorCode::kUnknown));
        return SequenceProgress::kCompleted;
    }
#else
    SequenceProgress prepareForSubmit(GHandle handle) override
    {
        for (size_t i = 0; i < kInlineTransitionCap; ++i) {
            const SequenceProgress progress = pump();
            if (progress == SequenceProgress::kCompleted) {
                return progress;
            }
            if (!m_has_active_task) {
                return SequenceProgress::kCompleted;
            }
            if (m_active_kind == ActiveKind::kRead) {
                if (!m_driver.recvContext().handleComplete(handle)) {
                    return SequenceProgress::kNeedWait;
                }
                auto io_result = std::move(m_driver.recvContext().m_result);
                clearActiveTask();
                m_driver.onRead(std::move(io_result));
                continue;
            }
            if (m_active_kind == ActiveKind::kWrite) {
                if (!m_driver.sendContext().handleComplete(handle)) {
                    return SequenceProgress::kNeedWait;
                }
                auto io_result = std::move(m_driver.sendContext().m_result);
                clearActiveTask();
                m_driver.onWrite(std::move(io_result));
                continue;
            }
            setFailure(SslError(SslErrorCode::kUnknown));
            return SequenceProgress::kCompleted;
        }
        setFailure(SslError(SslErrorCode::kUnknown));
        clearActiveTask();
        return SequenceProgress::kCompleted;
    }

    SequenceProgress onActiveEvent(GHandle handle) override
    {
        if (!m_has_active_task) {
            return prepareForSubmit(handle);
        }
        if (m_active_kind == ActiveKind::kRead) {
            if (!m_driver.recvContext().handleComplete(handle)) {
                return SequenceProgress::kNeedWait;
            }
            auto io_result = std::move(m_driver.recvContext().m_result);
            clearActiveTask();
            m_driver.onRead(std::move(io_result));
            return prepareForSubmit(handle);
        }
        if (m_active_kind == ActiveKind::kWrite) {
            if (!m_driver.sendContext().handleComplete(handle)) {
                return SequenceProgress::kNeedWait;
            }
            auto io_result = std::move(m_driver.sendContext().m_result);
            clearActiveTask();
            m_driver.onWrite(std::move(io_result));
            return prepareForSubmit(handle);
        }
        setFailure(SslError(SslErrorCode::kUnknown));
        return SequenceProgress::kCompleted;
    }
#endif

private:
    enum class ActiveKind : uint8_t {
        kNone,
        kRead,
        kWrite,
    };

    static constexpr size_t kInlineTransitionCap = 64;

    static SslError bridgeSequenceError(const IOError& error)
    {
        if (IOError::contains(error.code(), kTimeout)) {
            return SslError(SslErrorCode::kTimeout);
        }
        if (IOError::contains(error.code(), kDisconnectError)) {
            return SslError(SslErrorCode::kPeerClosed);
        }
        if (IOError::contains(error.code(), kReadFailed)) {
            return SslError(SslErrorCode::kReadFailed);
        }
        if (IOError::contains(error.code(), kWriteFailed)) {
            return SslError(SslErrorCode::kWriteFailed);
        }
        return SslError(SslErrorCode::kUnknown);
    }

    void setFailure(SslError error)
    {
        if constexpr (detail::is_expected_v<result_type>) {
            using ErrorT = typename detail::expected_traits<result_type>::error_type;
            if constexpr (std::is_constructible_v<ErrorT, SslError>) {
                m_result = std::unexpected(ErrorT(std::move(error)));
                m_result_set = true;
                return;
            }
        }
        m_error = std::move(error);
    }

    void activateRead()
    {
        m_active_task = IOTask{RECV, nullptr, &m_driver.recvContext()};
        m_has_active_task = true;
        m_active_kind = ActiveKind::kRead;
    }

    void activateWrite()
    {
        m_active_task = IOTask{SEND, nullptr, &m_driver.sendContext()};
        m_has_active_task = true;
        m_active_kind = ActiveKind::kWrite;
    }

    void clearActiveTask()
    {
        m_active_task = IOTask{};
        m_has_active_task = false;
        m_active_kind = ActiveKind::kNone;
    }

    void deliverDriverResult()
    {
        switch (m_running_signal) {
        case SslMachineSignal::kHandshake:
            m_machine.onHandshake(m_driver.takeHandshakeResult());
            break;
        case SslMachineSignal::kRecv:
            m_machine.onRecv(m_driver.takeRecvResult());
            break;
        case SslMachineSignal::kSend:
            m_machine.onSend(m_driver.takeSendResult());
            break;
        case SslMachineSignal::kShutdown:
            m_machine.onShutdown(m_driver.takeShutdownResult());
            break;
        default:
            setFailure(SslError(SslErrorCode::kUnknown));
            break;
        }
        m_running_signal = SslMachineSignal::kContinue;
    }

    SequenceProgress startAction(SslMachineAction<result_type> action)
    {
        switch (action.signal) {
        case SslMachineSignal::kContinue:
            return SequenceProgress::kNeedWait;
        case SslMachineSignal::kHandshake:
            m_running_signal = SslMachineSignal::kHandshake;
            m_driver.startHandshake();
            return SequenceProgress::kNeedWait;
        case SslMachineSignal::kRecv:
            if (action.read_buffer == nullptr && action.read_length != 0) {
                setFailure(SslError(SslErrorCode::kReadFailed));
                return SequenceProgress::kCompleted;
            }
            m_running_signal = SslMachineSignal::kRecv;
            m_driver.startRecv(action.read_buffer, action.read_length);
            return SequenceProgress::kNeedWait;
        case SslMachineSignal::kSend:
            if (action.write_buffer == nullptr && action.write_length != 0) {
                setFailure(SslError(SslErrorCode::kWriteFailed));
                return SequenceProgress::kCompleted;
            }
            m_running_signal = SslMachineSignal::kSend;
            m_driver.startSend(action.write_buffer, action.write_length);
            return SequenceProgress::kNeedWait;
        case SslMachineSignal::kShutdown:
            m_running_signal = SslMachineSignal::kShutdown;
            m_driver.startShutdown();
            return SequenceProgress::kNeedWait;
        case SslMachineSignal::kComplete:
            if (!action.result.has_value()) {
                setFailure(SslError(SslErrorCode::kUnknown));
                return SequenceProgress::kCompleted;
            }
            m_result = std::move(*action.result);
            m_result_set = true;
            return SequenceProgress::kCompleted;
        case SslMachineSignal::kFail:
            setFailure(action.error.value_or(SslError(SslErrorCode::kUnknown)));
            return SequenceProgress::kCompleted;
        }
        setFailure(SslError(SslErrorCode::kUnknown));
        return SequenceProgress::kCompleted;
    }

    SequenceProgress pump()
    {
        for (size_t i = 0; i < kInlineTransitionCap; ++i) {
            if (m_result_set || m_error.has_value()) {
                return SequenceProgress::kCompleted;
            }
            if (m_has_active_task) {
                return SequenceProgress::kNeedWait;
            }

            if (m_running_signal != SslMachineSignal::kContinue) {
                const auto wait = m_driver.poll();
                if (m_driver.completed()) {
                    deliverDriverResult();
                    continue;
                }
                if (wait.kind == SslOperationDriver::WaitKind::kRead) {
                    activateRead();
                    return SequenceProgress::kNeedWait;
                }
                if (wait.kind == SslOperationDriver::WaitKind::kWrite) {
                    activateWrite();
                    return SequenceProgress::kNeedWait;
                }
                setFailure(SslError(SslErrorCode::kUnknown));
                return SequenceProgress::kCompleted;
            }

            auto action = m_machine.advance();
            const SequenceProgress progress = startAction(std::move(action));
            if (progress == SequenceProgress::kCompleted) {
                return progress;
            }
            continue;
        }

        setFailure(SslError(SslErrorCode::kUnknown));
        clearActiveTask();
        return SequenceProgress::kCompleted;
    }

    SslSocket* m_socket = nullptr;
    MachineT m_machine;
    SslOperationDriver m_driver;
    IOTask m_active_task{};
    bool m_has_active_task = false;
    ActiveKind m_active_kind = ActiveKind::kNone;
    SslMachineSignal m_running_signal = SslMachineSignal::kContinue;
    bool m_context_bound = false;
    std::optional<result_type> m_result;
    bool m_result_set = false;
    std::optional<SslError> m_error;
};

template <SslAwaitableStateMachine MachineT>
class SslStateMachineBuilder
{
public:
    SslStateMachineBuilder(IOController* controller, SslSocket* socket, MachineT machine)
        : m_controller(controller)
        , m_socket(socket)
        , m_machine(std::move(machine)) {}

    auto build() & -> SslStateMachineAwaitable<MachineT>
    {
        return SslStateMachineAwaitable<MachineT>(m_controller, m_socket, std::move(m_machine));
    }

    auto build() && -> SslStateMachineAwaitable<MachineT>
    {
        return SslStateMachineAwaitable<MachineT>(m_controller, m_socket, std::move(m_machine));
    }

private:
    IOController* m_controller;
    SslSocket* m_socket;
    MachineT m_machine;
};

namespace detail {

struct SslSingleHandshakeMachine {
    using result_type = std::expected<void, SslError>;

    SslMachineAction<result_type> advance()
    {
        if (m_result.has_value()) {
            return SslMachineAction<result_type>::complete(std::move(*m_result));
        }
        return SslMachineAction<result_type>::handshake();
    }

    void onHandshake(std::expected<void, SslError> result) { m_result = std::move(result); }
    void onRecv(std::expected<Bytes, SslError>) {}
    void onSend(std::expected<size_t, SslError>) {}
    void onShutdown(std::expected<void, SslError>) {}

    std::optional<result_type> m_result;
};

struct SslSingleRecvMachine {
    using result_type = std::expected<Bytes, SslError>;

    SslSingleRecvMachine(char* buffer, size_t length)
        : m_buffer(buffer)
        , m_length(length) {}

    SslMachineAction<result_type> advance()
    {
        if (m_result.has_value()) {
            return SslMachineAction<result_type>::complete(std::move(*m_result));
        }
        return SslMachineAction<result_type>::recv(m_buffer, m_length);
    }

    void onHandshake(std::expected<void, SslError>) {}
    void onRecv(std::expected<Bytes, SslError> result) { m_result = std::move(result); }
    void onSend(std::expected<size_t, SslError>) {}
    void onShutdown(std::expected<void, SslError>) {}

    char* m_buffer = nullptr;
    size_t m_length = 0;
    std::optional<result_type> m_result;
};

struct SslSingleSendMachine {
    using result_type = std::expected<size_t, SslError>;

    SslSingleSendMachine(const char* buffer, size_t length)
        : m_buffer(buffer)
        , m_length(length) {}

    SslMachineAction<result_type> advance()
    {
        if (m_result.has_value()) {
            return SslMachineAction<result_type>::complete(std::move(*m_result));
        }
        return SslMachineAction<result_type>::send(m_buffer, m_length);
    }

    void onHandshake(std::expected<void, SslError>) {}
    void onRecv(std::expected<Bytes, SslError>) {}
    void onSend(std::expected<size_t, SslError> result) { m_result = std::move(result); }
    void onShutdown(std::expected<void, SslError>) {}

    const char* m_buffer = nullptr;
    size_t m_length = 0;
    std::optional<result_type> m_result;
};

struct SslSingleShutdownMachine {
    using result_type = std::expected<void, SslError>;

    SslMachineAction<result_type> advance()
    {
        if (m_result.has_value()) {
            return SslMachineAction<result_type>::complete(std::move(*m_result));
        }
        return SslMachineAction<result_type>::shutdown();
    }

    void onHandshake(std::expected<void, SslError>) {}
    void onRecv(std::expected<Bytes, SslError>) {}
    void onSend(std::expected<size_t, SslError>) {}
    void onShutdown(std::expected<void, SslError> result) { m_result = std::move(result); }

    std::optional<result_type> m_result;
};

template <typename ResultT, size_t InlineN, typename FlowT>
class SslLinearMachine
{
public:
    using result_type = ResultT;
    using OpsT = SslBuilderOps<ResultT, InlineN>;

    static constexpr size_t kInvalidIndex = static_cast<size_t>(-1);

    enum class NodeKind : uint8_t {
        kHandshake,
        kRecv,
        kSend,
        kShutdown,
        kParse,
        kLocal,
        kFinish,
    };

    using HandshakeHandlerFn = void(*)(FlowT*, OpsT&, SslHandshakeContext&);
    using RecvHandlerFn = void(*)(FlowT*, OpsT&, SslRecvContext&);
    using SendHandlerFn = void(*)(FlowT*, OpsT&, SslSendContext&);
    using ShutdownHandlerFn = void(*)(FlowT*, OpsT&, SslShutdownContext&);
    using LocalHandlerFn = void(*)(FlowT*, OpsT&);
    using ParseHandlerFn = ParseStatus(*)(FlowT*, OpsT&);

    struct Node {
        NodeKind kind = NodeKind::kLocal;
        HandshakeHandlerFn handshake_handler = nullptr;
        RecvHandlerFn recv_handler = nullptr;
        SendHandlerFn send_handler = nullptr;
        ShutdownHandlerFn shutdown_handler = nullptr;
        LocalHandlerFn local_handler = nullptr;
        ParseHandlerFn parse_handler = nullptr;
        char* read_buffer = nullptr;
        const char* write_buffer = nullptr;
        size_t io_length = 0;
        size_t parse_rearm_recv_index = kInvalidIndex;
    };

    using NodeList = std::vector<Node>;

    SslLinearMachine(IOController* controller, FlowT* flow, NodeList nodes)
        : m_flow(flow)
        , m_nodes(std::move(nodes))
    {
        (void)controller;
    }

    template <auto Handler>
    static Node makeHandshakeNode()
    {
        Node node;
        node.kind = NodeKind::kHandshake;
        node.handshake_handler = &invokeHandshake<Handler>;
        return node;
    }

    template <auto Handler>
    static Node makeRecvNode(char* buffer, size_t length)
    {
        Node node;
        node.kind = NodeKind::kRecv;
        node.recv_handler = &invokeRecv<Handler>;
        node.read_buffer = buffer;
        node.io_length = length;
        return node;
    }

    template <auto Handler>
    static Node makeSendNode(const char* buffer, size_t length)
    {
        Node node;
        node.kind = NodeKind::kSend;
        node.send_handler = &invokeSend<Handler>;
        node.write_buffer = buffer;
        node.io_length = length;
        return node;
    }

    template <auto Handler>
    static Node makeShutdownNode()
    {
        Node node;
        node.kind = NodeKind::kShutdown;
        node.shutdown_handler = &invokeShutdown<Handler>;
        return node;
    }

    template <auto Handler>
    static Node makeLocalNode()
    {
        Node node;
        node.kind = NodeKind::kLocal;
        node.local_handler = &invokeLocal<Handler>;
        return node;
    }

    template <auto Handler>
    static Node makeFinishNode()
    {
        Node node;
        node.kind = NodeKind::kFinish;
        node.local_handler = &invokeLocal<Handler>;
        return node;
    }

    template <auto Handler>
    static Node makeParseNode(size_t rearm_recv_index)
    {
        Node node;
        node.kind = NodeKind::kParse;
        node.parse_handler = &invokeParse<Handler>;
        node.parse_rearm_recv_index = rearm_recv_index;
        return node;
    }

    void onAwaitContext(const AwaitContext& ctx)
    {
        if constexpr (requires(FlowT& flow, const AwaitContext& context) {
            flow.onAwaitContext(context);
        }) {
            if (m_flow != nullptr) {
                m_flow->onAwaitContext(ctx);
            }
        }
    }

    SslMachineAction<result_type> advance()
    {
        if (m_result.has_value()) {
            return SslMachineAction<result_type>::complete(std::move(*m_result));
        }
        if (m_error.has_value()) {
            return SslMachineAction<result_type>::fail(*m_error);
        }
        if (m_cursor >= m_nodes.size()) {
            setError(SslError(SslErrorCode::kUnknown));
            return emitActionFromOutcome();
        }

        const Node& node = m_nodes[m_cursor];
        switch (node.kind) {
        case NodeKind::kHandshake:
            m_pending_kind = NodeKind::kHandshake;
            m_pending_index = m_cursor;
            return SslMachineAction<result_type>::handshake();
        case NodeKind::kRecv:
            m_recv_context.m_buffer = node.read_buffer;
            m_recv_context.m_length = node.io_length;
            m_pending_kind = NodeKind::kRecv;
            m_pending_index = m_cursor;
            return SslMachineAction<result_type>::recv(node.read_buffer, node.io_length);
        case NodeKind::kSend:
            m_send_context.m_buffer = node.write_buffer;
            m_send_context.m_length = node.io_length;
            m_pending_kind = NodeKind::kSend;
            m_pending_index = m_cursor;
            return SslMachineAction<result_type>::send(node.write_buffer, node.io_length);
        case NodeKind::kShutdown:
            m_pending_kind = NodeKind::kShutdown;
            m_pending_index = m_cursor;
            return SslMachineAction<result_type>::shutdown();
        case NodeKind::kParse:
            return runParse(node);
        case NodeKind::kLocal:
        case NodeKind::kFinish:
            return runLocal(node);
        }
        setError(SslError(SslErrorCode::kUnknown));
        return emitActionFromOutcome();
    }

    void onHandshake(std::expected<void, SslError> result)
    {
        if (m_pending_kind != NodeKind::kHandshake || m_pending_index >= m_nodes.size()) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }

        const bool has_value = result.has_value();
        std::optional<SslError> error;
        if (!has_value) {
            error = result.error();
        }
        m_handshake_context.m_result = std::move(result);

        const Node& node = m_nodes[m_pending_index];
        invokeHandshakeNode(node);
        clearPending();

        if (absorbOpsOutcome()) {
            return;
        }
        if (error.has_value()) {
            setError(std::move(*error));
            return;
        }
        ++m_cursor;
    }

    void onRecv(std::expected<Bytes, SslError> result)
    {
        if (m_pending_kind != NodeKind::kRecv || m_pending_index >= m_nodes.size()) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }

        const bool has_value = result.has_value();
        std::optional<SslError> error;
        if (!has_value) {
            error = result.error();
        }
        m_recv_context.m_result = std::move(result);

        const Node& node = m_nodes[m_pending_index];
        invokeRecvNode(node);
        clearPending();

        if (absorbOpsOutcome()) {
            return;
        }
        if (error.has_value()) {
            setError(std::move(*error));
            return;
        }
        ++m_cursor;
    }

    void onSend(std::expected<size_t, SslError> result)
    {
        if (m_pending_kind != NodeKind::kSend || m_pending_index >= m_nodes.size()) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }

        const bool has_value = result.has_value();
        std::optional<SslError> error;
        if (!has_value) {
            error = result.error();
        }
        m_send_context.m_result = std::move(result);

        const Node& node = m_nodes[m_pending_index];
        invokeSendNode(node);
        clearPending();

        if (absorbOpsOutcome()) {
            return;
        }
        if (error.has_value()) {
            setError(std::move(*error));
            return;
        }
        ++m_cursor;
    }

    void onShutdown(std::expected<void, SslError> result)
    {
        if (m_pending_kind != NodeKind::kShutdown || m_pending_index >= m_nodes.size()) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }

        const bool has_value = result.has_value();
        std::optional<SslError> error;
        if (!has_value) {
            error = result.error();
        }
        m_shutdown_context.m_result = std::move(result);

        const Node& node = m_nodes[m_pending_index];
        invokeShutdownNode(node);
        clearPending();

        if (absorbOpsOutcome()) {
            return;
        }
        if (error.has_value()) {
            setError(std::move(*error));
            return;
        }
        ++m_cursor;
    }

private:
    template <auto Handler>
    static void invokeHandshake(FlowT* flow, OpsT& ops, SslHandshakeContext& ctx)
    {
        (flow->*Handler)(ops, ctx);
    }

    template <auto Handler>
    static void invokeRecv(FlowT* flow, OpsT& ops, SslRecvContext& ctx)
    {
        (flow->*Handler)(ops, ctx);
    }

    template <auto Handler>
    static void invokeSend(FlowT* flow, OpsT& ops, SslSendContext& ctx)
    {
        (flow->*Handler)(ops, ctx);
    }

    template <auto Handler>
    static void invokeShutdown(FlowT* flow, OpsT& ops, SslShutdownContext& ctx)
    {
        (flow->*Handler)(ops, ctx);
    }

    template <auto Handler>
    static void invokeLocal(FlowT* flow, OpsT& ops)
    {
        (flow->*Handler)(ops);
    }

    template <auto Handler>
    static ParseStatus invokeParse(FlowT* flow, OpsT& ops)
    {
        return (flow->*Handler)(ops);
    }

    void invokeHandshakeNode(const Node& node)
    {
        if (node.handshake_handler == nullptr) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }
        m_ops_owner.reset();
        OpsT ops(m_ops_owner);
        node.handshake_handler(m_flow, ops, m_handshake_context);
    }

    void invokeRecvNode(const Node& node)
    {
        if (node.recv_handler == nullptr) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }
        m_ops_owner.reset();
        OpsT ops(m_ops_owner);
        node.recv_handler(m_flow, ops, m_recv_context);
    }

    void invokeSendNode(const Node& node)
    {
        if (node.send_handler == nullptr) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }
        m_ops_owner.reset();
        OpsT ops(m_ops_owner);
        node.send_handler(m_flow, ops, m_send_context);
    }

    void invokeShutdownNode(const Node& node)
    {
        if (node.shutdown_handler == nullptr) {
            setError(SslError(SslErrorCode::kUnknown));
            return;
        }
        m_ops_owner.reset();
        OpsT ops(m_ops_owner);
        node.shutdown_handler(m_flow, ops, m_shutdown_context);
    }

    SslMachineAction<result_type> runLocal(const Node& node)
    {
        if (node.local_handler == nullptr) {
            setError(SslError(SslErrorCode::kUnknown));
            return emitActionFromOutcome();
        }

        m_ops_owner.reset();
        OpsT ops(m_ops_owner);
        node.local_handler(m_flow, ops);

        if (absorbOpsOutcome()) {
            return emitActionFromOutcome();
        }
        ++m_cursor;
        return SslMachineAction<result_type>::continue_();
    }

    SslMachineAction<result_type> runParse(const Node& node)
    {
        if (node.parse_handler == nullptr) {
            setError(SslError(SslErrorCode::kUnknown));
            return emitActionFromOutcome();
        }

        m_ops_owner.reset();
        OpsT ops(m_ops_owner);
        const ParseStatus status = node.parse_handler(m_flow, ops);

        if (absorbOpsOutcome()) {
            return emitActionFromOutcome();
        }

        switch (status) {
        case ParseStatus::kNeedMore:
            if (node.parse_rearm_recv_index == kInvalidIndex ||
                node.parse_rearm_recv_index >= m_nodes.size() ||
                m_nodes[node.parse_rearm_recv_index].kind != NodeKind::kRecv) {
                setError(SslError(SslErrorCode::kUnknown));
                return emitActionFromOutcome();
            }
            m_cursor = node.parse_rearm_recv_index;
            return SslMachineAction<result_type>::continue_();
        case ParseStatus::kContinue:
            return SslMachineAction<result_type>::continue_();
        case ParseStatus::kCompleted:
            ++m_cursor;
            return SslMachineAction<result_type>::continue_();
        }
        setError(SslError(SslErrorCode::kUnknown));
        return emitActionFromOutcome();
    }

    bool absorbOpsOutcome()
    {
        if (m_ops_owner.hasResultValue()) {
            auto result = m_ops_owner.takeResultValue();
            if (result.has_value()) {
                m_result = std::move(*result);
            } else {
                setError(SslError(SslErrorCode::kUnknown));
            }
            return true;
        }
        if (m_ops_owner.queueUsed()) {
            m_ops_owner.clear();
            setError(SslError(SslErrorCode::kUnknown));
            return true;
        }
        return false;
    }

    void setError(SslError error)
    {
        if constexpr (detail::is_expected_v<result_type>) {
            using ErrorT = typename detail::expected_traits<result_type>::error_type;
            if constexpr (std::is_constructible_v<ErrorT, SslError>) {
                m_result = std::unexpected(ErrorT(std::move(error)));
                return;
            }
        }
        m_error = std::move(error);
    }

    SslMachineAction<result_type> emitActionFromOutcome()
    {
        if (m_result.has_value()) {
            return SslMachineAction<result_type>::complete(std::move(*m_result));
        }
        if (m_error.has_value()) {
            return SslMachineAction<result_type>::fail(*m_error);
        }
        return SslMachineAction<result_type>::continue_();
    }

    void clearPending()
    {
        m_pending_kind = NodeKind::kLocal;
        m_pending_index = kInvalidIndex;
    }

    FlowT* m_flow = nullptr;
    NodeList m_nodes;
    size_t m_cursor = 0;
    NodeKind m_pending_kind = NodeKind::kLocal;
    size_t m_pending_index = kInvalidIndex;
    size_t m_last_recv_index = kInvalidIndex;

    SslBuilderOutcome<ResultT> m_ops_owner;
    SslHandshakeContext m_handshake_context;
    SslRecvContext m_recv_context;
    SslSendContext m_send_context;
    SslShutdownContext m_shutdown_context;
    std::optional<result_type> m_result;
    std::optional<SslError> m_error;
};

} // namespace detail

template <typename ResultT, size_t InlineN = 4, typename FlowT = void>
class SslAwaitableBuilder
{
public:
    using MachineT = detail::SslLinearMachine<ResultT, InlineN, FlowT>;
    using MachineNode = typename MachineT::Node;

    SslAwaitableBuilder(IOController* controller, SslSocket* socket, FlowT& flow)
        : m_controller(controller)
        , m_socket(socket)
        , m_flow(&flow)
    {
        m_nodes.reserve(InlineN);
    }

    template <SslAwaitableStateMachine MachineTParam>
    static auto fromStateMachine(IOController* controller, SslSocket* socket, MachineTParam machine)
        -> SslStateMachineBuilder<MachineTParam>
    {
        static_assert(std::same_as<typename MachineTParam::result_type, ResultT>,
                      "SslAwaitableBuilder::fromStateMachine requires matching result_type");
        return SslStateMachineBuilder<MachineTParam>(controller, socket, std::move(machine));
    }

    template <auto Handler>
    SslAwaitableBuilder& handshake()
    {
        m_nodes.push_back(MachineT::template makeHandshakeNode<Handler>());
        return *this;
    }

    template <auto Handler>
    SslAwaitableBuilder& recv(char* buffer, size_t length)
    {
        m_nodes.push_back(MachineT::template makeRecvNode<Handler>(buffer, length));
        m_last_recv_index = m_nodes.size() - 1;
        return *this;
    }

    template <auto Handler>
    SslAwaitableBuilder& send(const char* buffer, size_t length)
    {
        m_nodes.push_back(MachineT::template makeSendNode<Handler>(buffer, length));
        return *this;
    }

    template <auto Handler>
    SslAwaitableBuilder& shutdown()
    {
        m_nodes.push_back(MachineT::template makeShutdownNode<Handler>());
        return *this;
    }

    template <auto Handler>
    SslAwaitableBuilder& local()
    {
        m_nodes.push_back(MachineT::template makeLocalNode<Handler>());
        return *this;
    }

    template <auto Handler>
    SslAwaitableBuilder& parse()
    {
        m_nodes.push_back(MachineT::template makeParseNode<Handler>(m_last_recv_index));
        return *this;
    }

    template <auto Handler>
    SslAwaitableBuilder& finish()
    {
        m_nodes.push_back(MachineT::template makeFinishNode<Handler>());
        return *this;
    }

    auto build() & -> SslStateMachineAwaitable<MachineT>
    {
        return buildImpl();
    }

    auto build() && -> SslStateMachineAwaitable<MachineT>
    {
        return buildImpl();
    }

private:
    auto buildImpl() -> SslStateMachineAwaitable<MachineT>
    {
        return SslStateMachineAwaitable<MachineT>(
            m_controller,
            m_socket,
            MachineT(m_controller, m_flow, std::move(m_nodes))
        );
    }

    IOController* m_controller;
    SslSocket* m_socket;
    FlowT* m_flow;
    std::vector<MachineNode> m_nodes;
    size_t m_last_recv_index = MachineT::kInvalidIndex;
};

template <typename ResultT, size_t InlineN>
class SslAwaitableBuilder<ResultT, InlineN, void>
{
public:
    template <SslAwaitableStateMachine MachineT>
    static auto fromStateMachine(IOController* controller, SslSocket* socket, MachineT machine)
        -> SslStateMachineBuilder<MachineT>
    {
        static_assert(std::same_as<typename MachineT::result_type, ResultT>,
                      "SslAwaitableBuilder::fromStateMachine requires matching result_type");
        return SslStateMachineBuilder<MachineT>(controller, socket, std::move(machine));
    }
};

} // namespace galay::ssl

#endif // GALAY_SSL_AWAITABLE_CORE_H
