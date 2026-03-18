#ifndef GALAY_SSL_AWAITABLE_H
#define GALAY_SSL_AWAITABLE_H

#include "SslAwaitableCore.h"

namespace galay::ssl
{

struct SslRecvAwaitable
    : public SslStateMachineAwaitable<detail::SslSingleRecvMachine>,
      public TimeoutSupport<SslRecvAwaitable> {
    using Base = SslStateMachineAwaitable<detail::SslSingleRecvMachine>;

    SslRecvAwaitable(IOController* controller, SslSocket* socket,
                     char* buffer, size_t length)
        : Base(controller, socket, detail::SslSingleRecvMachine(buffer, length)) {}

    using Base::await_ready;
    using Base::await_resume;
    using Base::await_suspend;
};

struct SslSendAwaitable : public SslStateMachineAwaitable<detail::SslSingleSendMachine> {
    using Base = SslStateMachineAwaitable<detail::SslSingleSendMachine>;

    SslSendAwaitable(IOController* controller, SslSocket* socket,
                     const char* buffer, size_t length)
        : Base(controller, socket, detail::SslSingleSendMachine(buffer, length)) {}

    using Base::await_ready;
    using Base::await_resume;
    using Base::await_suspend;
};

struct SslHandshakeAwaitable : public SslStateMachineAwaitable<detail::SslSingleHandshakeMachine> {
    using Base = SslStateMachineAwaitable<detail::SslSingleHandshakeMachine>;

    SslHandshakeAwaitable(IOController* controller, SslSocket* socket)
        : Base(controller, socket, detail::SslSingleHandshakeMachine{}) {}

    using Base::await_ready;
    using Base::await_resume;
    using Base::await_suspend;
};

struct SslShutdownAwaitable : public SslStateMachineAwaitable<detail::SslSingleShutdownMachine> {
    using Base = SslStateMachineAwaitable<detail::SslSingleShutdownMachine>;

    SslShutdownAwaitable(IOController* controller, SslSocket* socket)
        : Base(controller, socket, detail::SslSingleShutdownMachine{}) {}

    using Base::await_ready;
    using Base::await_resume;
    using Base::await_suspend;
};

} // namespace galay::ssl

#endif // GALAY_SSL_AWAITABLE_H
