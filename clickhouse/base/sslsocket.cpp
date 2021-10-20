#include "sslsocket.h"

#include <stdexcept>

#include <openssl/ssl.h>
#include <openssl/err.h>

//#include <iostream>

namespace {

void throwSSLError(int error, const char * /*location*/, const char * /*statement*/) {
    char buffer[256] = {'\0'};
    const auto detail_error = ERR_get_error();
    ERR_error_string_n(detail_error, buffer, sizeof(buffer));
    auto reason = buffer; //reason ? reason : "Unknown SSL error";

//    std::cerr << "!!! SSL error at " << location
//              << "\n\tcaused by " << statement
//              << "\n\t: "<< reason << "(" << error << ")"
//              << "\n\t last err: " << ERR_peek_last_error()
//              << std::endl;

    throw std::runtime_error(std::string("OpenSSL error: ") + std::to_string(error) + " : " + reason);
}

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)
#define LOCATION __FILE__  ":" STRINGIFY(__LINE__)

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

#define HANDLE_SSL_CTX_ERROR(statement) do { \
    if (const auto ret_code = statement; !ret_code) \
        throwSSLError(ERR_peek_error(), LOCATION, STRINGIFY(statement)); \
} while(false);

    if (context_params.use_default_ca_locations)
        HANDLE_SSL_CTX_ERROR(SSL_CTX_set_default_verify_paths(ctx.get()));
    if (!context_params.path_to_ca_directory.empty())
        HANDLE_SSL_CTX_ERROR(
            SSL_CTX_load_verify_locations(
                ctx.get(),
                nullptr,
                context_params.path_to_ca_directory.c_str())
        );
    for (const auto & f : context_params.path_to_ca_files)
    {
        HANDLE_SSL_CTX_ERROR(SSL_CTX_load_verify_locations(ctx.get(), f.c_str(), nullptr));
    }

    if (context_params.context_options != -1)
        SSL_CTX_set_options(ctx.get(), context_params.context_options);
    if (context_params.min_protocol_version != -1)
        HANDLE_SSL_CTX_ERROR(
            SSL_CTX_set_min_proto_version(ctx.get(), context_params.min_protocol_version));
    if (context_params.max_protocol_version != -1)
        HANDLE_SSL_CTX_ERROR(
            SSL_CTX_set_max_proto_version(ctx.get(), context_params.max_protocol_version));

    return ctx.release();
}



}

#define HANDLE_SSL_ERROR(statement) do { \
    if (const auto ret_code = statement; ret_code <= 0) \
        throwSSLError(SSL_get_error(ssl_, ret_code), LOCATION, STRINGIFY(statement)); \
} while(false);

namespace clickhouse {

SSLContext::SSLContext(SSL_CTX & context)
    : context_(&context)
{
    SSL_CTX_up_ref(context_);
}

SSLContext::SSLContext(const SSLContextParams & context_params)
    : context_(prepareSSLContext(context_params))
{
}

SSLContext::~SSLContext() {
    SSL_CTX_free(context_);
}

SSL_CTX * SSLContext::getContext() {
    return context_;
}

//#define LOG_SSL_STATE() std::cerr << "!!!!" << LOCATION << " @" << __FUNCTION__ \
//    << "\t" << SSL_get_version(ssl_) << " state: "  << SSL_state_string_long(ssl_) \
//    << "\n\t handshake state: " << SSL_get_state(ssl_) \
//    << std::endl
SSLSocket::SSLSocket(const NetworkAddress& addr, SSLContext& context)
    : Socket(addr),
    ssl_(SSL_new(context.getContext()))
{

    if (!ssl_)
        throw std::runtime_error("Failed to create SSL instance");

    HANDLE_SSL_ERROR(SSL_set_fd(ssl_, handle_));
    SSL_set_connect_state(ssl_);
    HANDLE_SSL_ERROR(SSL_connect(ssl_));
    HANDLE_SSL_ERROR(SSL_set_mode(ssl_, SSL_MODE_AUTO_RETRY));

    if(const auto verify_result = SSL_get_verify_result(ssl_); verify_result != X509_V_OK) {
        throw std::runtime_error("Failed to verify SSL connection, X509_v error: " + std::to_string(verify_result));
    }

//    auto ssl_session = SSL_get_session(ssl_);
//    if (ssl_session)
//    {
//        auto protocol_version = SSL_SESSION_get_protocol_version(ssl_session);
//        std::cerr << "SSL protocol version: " << protocol_version << std::endl;
//    }
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
    HANDLE_SSL_ERROR(SSL_read_ex(ssl_, buf, len, &actually_read));
    return actually_read;
}

SSLSocketOutput::SSLSocketOutput(SSL *ssl)
    : ssl_(ssl)
{}

SSLSocketOutput::~SSLSocketOutput() = default;

void SSLSocketOutput::DoWrite(const void* data, size_t len) {
    HANDLE_SSL_ERROR(SSL_write(ssl_, data, len));
}

}
