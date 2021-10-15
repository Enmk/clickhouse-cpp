#pragma once

#include "socket.h"

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

namespace clickhouse {

struct SSLContextParams
{
    std::vector<std::string> path_to_cert_files;
    std::string path_to_cert_directory;
    bool use_default_CA_locations;
};

class SSLContext
{
public:
    explicit SSLContext(SSL_CTX & context);
    explicit SSLContext(const SSLContextParams & context_params);
    ~SSLContext();

    SSLContext(const SSLContext &) = delete;
    SSLContext& operator=(const SSLContext &) = delete;
    SSLContext(SSLContext &&) = delete;
    SSLContext& operator=(SSLContext &) = delete;

private:
    friend class SSLSocket;
    SSL_CTX * getContext();

private:
    const bool owned;
    SSL_CTX * const context_;
};

class SSLSocket : public Socket {
public:
    explicit SSLSocket(const NetworkAddress& addr, SSLContext& context);
    SSLSocket(SSLSocket &&) = default;
    ~SSLSocket();

    SSLSocket(const SSLSocket & ) = delete;
    SSLSocket& operator=(const SSLSocket & ) = delete;

    std::unique_ptr<InputStream> makeInputStream() const override;
    std::unique_ptr<OutputStream> makeOutputStream() const override;

private:
    SSL *ssl_;
};

class SSLSocketInput : public InputStream {
public:
    explicit SSLSocketInput(SSL *ssl);
    ~SSLSocketInput();

protected:
    size_t DoRead(void* buf, size_t len) override;

private:
    SSL *ssl_;
};

class SSLSocketOutput : public OutputStream {
public:
    explicit SSLSocketOutput(SSL *ssl);
    ~SSLSocketOutput();

protected:
    void DoWrite(const void* data, size_t len) override;

private:
    SSL *ssl_;
};

}
