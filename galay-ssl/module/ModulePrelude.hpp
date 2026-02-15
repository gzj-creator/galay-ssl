#pragma once
// Auto prelude for transitional C++23 module builds on Clang/GCC/MSVC.
// Keep third-party/system/dependency headers in global module fragment.

#if __has_include(<algorithm>)
#include <algorithm>
#endif
#if __has_include(<cerrno>)
#include <cerrno>
#endif
#if __has_include(<coroutine>)
#include <coroutine>
#endif
#if __has_include(<cstdint>)
#include <cstdint>
#endif
#if __has_include(<cstring>)
#include <cstring>
#endif
#if __has_include(<expected>)
#include <expected>
#endif
#if __has_include(<functional>)
#include <functional>
#endif
#if __has_include(<galay-kernel/common/Bytes.h>)
#include <galay-kernel/common/Bytes.h>
#endif
#if __has_include(<galay-kernel/common/Defn.hpp>)
#include <galay-kernel/common/Defn.hpp>
#endif
#if __has_include(<galay-kernel/common/HandleOption.h>)
#include <galay-kernel/common/HandleOption.h>
#endif
#if __has_include(<galay-kernel/common/Host.hpp>)
#include <galay-kernel/common/Host.hpp>
#endif
#if __has_include(<galay-kernel/kernel/Awaitable.h>)
#include <galay-kernel/kernel/Awaitable.h>
#endif
#if __has_include(<galay-kernel/kernel/IOScheduler.hpp>)
#include <galay-kernel/kernel/IOScheduler.hpp>
#endif
#if __has_include(<galay-kernel/kernel/Timeout.hpp>)
#include <galay-kernel/kernel/Timeout.hpp>
#endif
#if __has_include(<galay-kernel/kernel/Waker.h>)
#include <galay-kernel/kernel/Waker.h>
#endif
#if __has_include(<limits>)
#include <limits>
#endif
#if __has_include(<memory>)
#include <memory>
#endif
#if __has_include(<netinet/in.h>)
#include <netinet/in.h>
#endif
#if __has_include(<openssl/err.h>)
#include <openssl/err.h>
#endif
#if __has_include(<openssl/ssl.h>)
#include <openssl/ssl.h>
#endif
#if __has_include(<openssl/x509.h>)
#include <openssl/x509.h>
#endif
#if __has_include(<sstream>)
#include <sstream>
#endif
#if __has_include(<string>)
#include <string>
#endif
#if __has_include(<string_view>)
#include <string_view>
#endif
#if __has_include(<sys/event.h>)
#include <sys/event.h>
#endif
#if __has_include(<sys/socket.h>)
#include <sys/socket.h>
#endif
#if __has_include(<unistd.h>)
#include <unistd.h>
#endif
#if __has_include(<vector>)
#include <vector>
#endif
#if __has_include("galay-ssl/async/Awaitable.h")
#include "galay-ssl/async/Awaitable.h"
#endif
#if __has_include("galay-ssl/async/SslSocket.h")
#include "galay-ssl/async/SslSocket.h"
#endif
#if __has_include("galay-ssl/common/Defn.hpp")
#include "galay-ssl/common/Defn.hpp"
#endif
#if __has_include("galay-ssl/common/Error.h")
#include "galay-ssl/common/Error.h"
#endif
#if __has_include("galay-ssl/module/ModulePrelude.hpp")
#include "galay-ssl/module/ModulePrelude.hpp"
#endif
#if __has_include("galay-ssl/ssl/SslContext.h")
#include "galay-ssl/ssl/SslContext.h"
#endif
#if __has_include("galay-ssl/ssl/SslEngine.h")
#include "galay-ssl/ssl/SslEngine.h"
#endif
