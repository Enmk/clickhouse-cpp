#include "sslsocket.h"

#include <stdexcept>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>

namespace {

void throwSSLError(int error, const char * location, const char * statement) {
    auto reason = ERR_reason_error_string(error);
    reason = reason ? reason : "Unknown SSL error";

    std::cerr << "!!! SSL error at " << location
              << "\n\tcaused by " << statement
              << "\n\t: "<< reason << "(" << error << ")" << std::endl;

    throw std::runtime_error(std::string("OpenSSL error: ") + std::to_string(error) + " : " + reason);
}

struct SSLInitializer {
    SSLInitializer() {
        SSL_library_init();
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();
    }
};

SSL_CTX * prepareSSLContext(const clickhouse::SSLContextParams & context_params) {
    static const SSLInitializer ssl_initializer;

    const SSL_METHOD *method = TLS_client_method();
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(method), &SSL_CTX_free);

    if (!ctx)
        throw std::runtime_error("Failed to initialize SSL context");

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)
#define LOCATION __FILE__  ":" STRINGIFY(__LINE__)

#define HANDLE_SSL_CTX_ERROR(statement) do { \
    if (const auto ret_code = statement; ret_code) \
        throwSSLError(ERR_get_error(), LOCATION, STRINGIFY(statement)); \
} while(false);

    if (context_params.use_default_CA_locations)
        HANDLE_SSL_CTX_ERROR(SSL_CTX_set_default_verify_paths(ctx.get()));
    if (!context_params.path_to_cert_directory.empty())
        HANDLE_SSL_CTX_ERROR(SSL_CTX_load_verify_locations(
                ctx.get(),
                nullptr,
                context_params.path_to_cert_directory.c_str())
        );
    for (const auto & f : context_params.path_to_cert_files)
    {
        HANDLE_SSL_CTX_ERROR(SSL_CTX_load_verify_locations(ctx.get(), f.c_str(), nullptr));
    }

    return ctx.release();
}



}

#define HANDLE_SSL_ERROR(statement) do { \
    if (const auto ret_code = statement; ret_code) \
        throwSSLError(SSL_get_error(ssl_, ret_code), LOCATION, STRINGIFY(statement)); \
} while(false);

namespace clickhouse {

SSLContext::SSLContext(SSL_CTX & context)
    : owned(false),
      context_(&context)
{
}

SSLContext::SSLContext(const SSLContextParams & context_params)
    : owned(true),
      context_(prepareSSLContext(context_params))
{
}

SSLContext::~SSLContext() {
    if (owned)
        SSL_CTX_free(context_);
}

SSL_CTX * SSLContext::getContext() {
    return context_;
}
#define LOG_SSL_STATE() std::cerr << "!!!!" << LOCATION << " @" << __FUNCTION__ \
    << " state "  << SSL_state_string_long(ssl_) << std::endl

SSLSocket::SSLSocket(const NetworkAddress& addr, SSLContext& context)
    : Socket(addr),
    ssl_(SSL_new(context.getContext()))
{

    if (!ssl_)
        throw std::runtime_error("Failed to create SSL instance");

    LOG_SSL_STATE();
    HANDLE_SSL_ERROR(SSL_set_fd(ssl_, handle_));
    HANDLE_SSL_ERROR(SSL_connect(ssl_));
    LOG_SSL_STATE();
    HANDLE_SSL_ERROR(SSL_set_mode(ssl_, SSL_MODE_AUTO_RETRY));
    LOG_SSL_STATE();

    if(const auto verify_result = SSL_get_verify_result(ssl_); verify_result != X509_V_OK) {
        throw std::runtime_error("Failed to verify SSL connection, X509_v error: " + std::to_string(verify_result));
    }
    auto ssl_session = SSL_get_session(ssl_);
    LOG_SSL_STATE();

    if (ssl_session)
    {
        auto protocol_version = SSL_SESSION_get_protocol_version(ssl_session);
        std::cerr << "SSL protocol version: " << protocol_version << std::endl;
    }
}

SSLSocket::~SSLSocket() {
    SSL_free(ssl_);
}

std::unique_ptr<InputStream> SSLSocket::makeInputStream() const {
    return std::make_unique<SSLSocketInput>(ssl_);
}

std::unique_ptr<OutputStream> SSLSocket::makeOutputStream() const {
    return std::make_unique<SSLSocketOutput>(ssl_);
}

SSLSocketInput::SSLSocketInput(SSL *ssl)
    : ssl_(ssl)
{}

SSLSocketInput::~SSLSocketInput() = default;

size_t SSLSocketInput::DoRead(void* buf, size_t len) {
    size_t actually_read;
    LOG_SSL_STATE();
    HANDLE_SSL_ERROR(SSL_read_ex(ssl_, buf, len, &actually_read));
    LOG_SSL_STATE();
    return actually_read;
}

SSLSocketOutput::SSLSocketOutput(SSL *ssl)
    : ssl_(ssl)
{}

SSLSocketOutput::~SSLSocketOutput() = default;

void SSLSocketOutput::DoWrite(const void* data, size_t len) {
    LOG_SSL_STATE();
    HANDLE_SSL_ERROR(SSL_write(ssl_, data, len));
    LOG_SSL_STATE();
}

}
