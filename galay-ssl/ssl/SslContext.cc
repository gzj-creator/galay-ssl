#include "SslContext.h"
#include <cstring>

namespace galay::ssl
{

namespace {

// 全局初始化标志
static bool g_ssl_initialized = false;

void initializeOpenSSL() {
    if (!g_ssl_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        g_ssl_initialized = true;
    }
}

const SSL_METHOD* getMethod(SslMethod method) {
    switch (method) {
        case SslMethod::TLS_Client:
            return TLS_client_method();
        case SslMethod::TLS_Server:
            return TLS_server_method();
        case SslMethod::TLS_1_2_Client:
        case SslMethod::TLS_1_2_Server:
            return TLS_method();
        case SslMethod::TLS_1_3_Client:
        case SslMethod::TLS_1_3_Server:
            return TLS_method();
        case SslMethod::DTLS_Client:
            return DTLS_client_method();
        case SslMethod::DTLS_Server:
            return DTLS_server_method();
        default:
            return TLS_method();
    }
}

} // anonymous namespace

SslContext::SslContext(SslMethod method)
    : m_ctx(nullptr)
{
    initializeOpenSSL();

    m_ctx = SSL_CTX_new(getMethod(method));
    if (!m_ctx) {
        m_error = SslError::fromOpenSSL(SslErrorCode::kContextCreateFailed);
        return;
    }

    // 设置默认选项
    SSL_CTX_set_options(m_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // 启用 Session 缓存以提高性能（减少完整握手次数）
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_timeout(m_ctx, 300);  // Session 有效期 5 分钟

    // 根据方法设置版本限制
    switch (method) {
        case SslMethod::TLS_1_2_Client:
        case SslMethod::TLS_1_2_Server:
            SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);
            SSL_CTX_set_max_proto_version(m_ctx, TLS1_2_VERSION);
            break;
        case SslMethod::TLS_1_3_Client:
        case SslMethod::TLS_1_3_Server:
            SSL_CTX_set_min_proto_version(m_ctx, TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(m_ctx, TLS1_3_VERSION);
            break;
        default:
            // 使用默认版本范围
            break;
    }
}

SslContext::~SslContext()
{
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
}

SslContext::SslContext(SslContext&& other) noexcept
    : m_ctx(other.m_ctx)
    , m_error(std::move(other.m_error))
    , m_verifyCallback(std::move(other.m_verifyCallback))
{
    other.m_ctx = nullptr;
}

SslContext& SslContext::operator=(SslContext&& other) noexcept
{
    if (this != &other) {
        if (m_ctx) {
            SSL_CTX_free(m_ctx);
        }
        m_ctx = other.m_ctx;
        m_error = std::move(other.m_error);
        m_verifyCallback = std::move(other.m_verifyCallback);
        other.m_ctx = nullptr;
    }
    return *this;
}

std::expected<void, SslError> SslContext::loadCertificate(
    const std::string& certFile,
    SslFileType type)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_use_certificate_file(m_ctx, certFile.c_str(), static_cast<int>(type)) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kCertificateLoadFailed));
    }

    return {};
}

std::expected<void, SslError> SslContext::loadCertificateChain(const std::string& certChainFile)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_use_certificate_chain_file(m_ctx, certChainFile.c_str()) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kCertificateLoadFailed));
    }

    return {};
}

std::expected<void, SslError> SslContext::loadPrivateKey(
    const std::string& keyFile,
    SslFileType type)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx, keyFile.c_str(), static_cast<int>(type)) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kPrivateKeyLoadFailed));
    }

    // 验证私钥与证书匹配
    if (SSL_CTX_check_private_key(m_ctx) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kPrivateKeyMismatch));
    }

    return {};
}

std::expected<void, SslError> SslContext::loadCACertificate(const std::string& caFile)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_load_verify_locations(m_ctx, caFile.c_str(), nullptr) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kCACertificateLoadFailed));
    }

    return {};
}

std::expected<void, SslError> SslContext::loadCAPath(const std::string& caPath)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_load_verify_locations(m_ctx, nullptr, caPath.c_str()) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kCACertificateLoadFailed));
    }

    return {};
}

std::expected<void, SslError> SslContext::useDefaultCA()
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_set_default_verify_paths(m_ctx) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kCACertificateLoadFailed));
    }

    return {};
}

void SslContext::setVerifyMode(SslVerifyMode mode,
                                std::function<bool(bool, X509_STORE_CTX*)> callback)
{
    if (!m_ctx) return;

    m_verifyCallback = std::move(callback);

    if (m_verifyCallback) {
        // 设置带回调的验证
        SSL_CTX_set_verify(m_ctx, static_cast<int>(mode),
            [](int preverify_ok, X509_STORE_CTX* ctx) -> int {
                // 获取 SSL 对象
                SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(
                    ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
                if (!ssl) return preverify_ok;

                // 获取 SSL_CTX
                SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);
                if (!ssl_ctx) return preverify_ok;

                // 获取 SslContext 指针
                SslContext* self = static_cast<SslContext*>(SSL_CTX_get_ex_data(ssl_ctx, 0));
                if (!self || !self->m_verifyCallback) return preverify_ok;

                return self->m_verifyCallback(preverify_ok != 0, ctx) ? 1 : 0;
            });

        // 存储 this 指针
        SSL_CTX_set_ex_data(m_ctx, 0, this);
    } else {
        SSL_CTX_set_verify(m_ctx, static_cast<int>(mode), nullptr);
    }
}

void SslContext::setVerifyDepth(int depth)
{
    if (m_ctx) {
        SSL_CTX_set_verify_depth(m_ctx, depth);
    }
}

std::expected<void, SslError> SslContext::setCiphers(const std::string& ciphers)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_set_cipher_list(m_ctx, ciphers.c_str()) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kUnknown));
    }

    return {};
}

std::expected<void, SslError> SslContext::setCiphersuites(const std::string& ciphersuites)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    if (SSL_CTX_set_ciphersuites(m_ctx, ciphersuites.c_str()) != 1) {
        return std::unexpected(SslError::fromOpenSSL(SslErrorCode::kUnknown));
    }

    return {};
}

std::expected<void, SslError> SslContext::setALPNProtocols(const std::vector<std::string>& protocols)
{
    if (!m_ctx) {
        return std::unexpected(SslError(SslErrorCode::kContextCreateFailed));
    }

    // 构建 ALPN 协议字符串（长度前缀格式）
    std::vector<unsigned char> alpn;
    for (const auto& proto : protocols) {
        if (proto.size() > 255) continue;
        alpn.push_back(static_cast<unsigned char>(proto.size()));
        alpn.insert(alpn.end(), proto.begin(), proto.end());
    }

    if (SSL_CTX_set_alpn_protos(m_ctx, alpn.data(), static_cast<unsigned int>(alpn.size())) != 0) {
        return std::unexpected(SslError(SslErrorCode::kALPNSetFailed));
    }

    return {};
}

void SslContext::setMinProtocolVersion(int version)
{
    if (m_ctx) {
        SSL_CTX_set_min_proto_version(m_ctx, version);
    }
}

void SslContext::setMaxProtocolVersion(int version)
{
    if (m_ctx) {
        SSL_CTX_set_max_proto_version(m_ctx, version);
    }
}

void SslContext::setSessionCacheMode(long mode)
{
    if (m_ctx) {
        SSL_CTX_set_session_cache_mode(m_ctx, mode);
    }
}

void SslContext::setSessionTimeout(long timeout)
{
    if (m_ctx) {
        SSL_CTX_set_timeout(m_ctx, timeout);
    }
}

} // namespace galay::ssl
