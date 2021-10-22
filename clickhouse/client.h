#pragma once

#include "query.h"
#include "exceptions.h"

#include "columns/array.h"
#include "columns/date.h"
#include "columns/decimal.h"
#include "columns/enum.h"
#include "columns/ip4.h"
#include "columns/ip6.h"
#include "columns/lowcardinality.h"
#include "columns/nullable.h"
#include "columns/numeric.h"
#include "columns/string.h"
#include "columns/tuple.h"
#include "columns/uuid.h"

#include <chrono>
#include <memory>
#include <ostream>
#include <string>

#if WITH_OPENSSL
typedef struct ssl_ctx_st SSL_CTX;
#endif

namespace clickhouse {

struct ServerInfo {
    std::string name;
    std::string timezone;
    std::string display_name;
    uint64_t    version_major;
    uint64_t    version_minor;
    uint64_t    version_patch;
    uint64_t    revision;
};

/// Methods of block compression.
enum class CompressionMethod {
    None    = -1,
    LZ4     =  1,
};

struct ClientOptions {
    ClientOptions() = default;
    ClientOptions(const ClientOptions &) = default;
    ClientOptions& operator=(const ClientOptions &) = default;
    ClientOptions(ClientOptions &&) = default;
    ClientOptions& operator=(ClientOptions &&) = default;

#define DECLARE_FIELD(name, type, setter, default_value) \
    type name = default_value; \
    inline ClientOptions& setter(const type& value) { \
        name = value; \
        return *this; \
    }

    /// Hostname of the server.
    DECLARE_FIELD(host, std::string, SetHost, std::string());
    /// Service port.
    DECLARE_FIELD(port, unsigned int, SetPort, 9000);

    /// Default database.
    DECLARE_FIELD(default_database, std::string, SetDefaultDatabase, "default");
    /// User name.
    DECLARE_FIELD(user, std::string, SetUser, "default");
    /// Access password.
    DECLARE_FIELD(password, std::string, SetPassword, std::string());

    /// By default all exceptions received during query execution will be
    /// passed to OnException handler.  Set rethrow_exceptions to true to
    /// enable throwing exceptions with standard c++ exception mechanism.
    DECLARE_FIELD(rethrow_exceptions, bool, SetRethrowException, true);

    /// Ping server every time before execute any query.
    DECLARE_FIELD(ping_before_query, bool, SetPingBeforeQuery, false);
    /// Count of retry to send request to server.
    DECLARE_FIELD(send_retries, unsigned int, SetSendRetries, 1);
    /// Amount of time to wait before next retry.
    DECLARE_FIELD(retry_timeout, std::chrono::seconds, SetRetryTimeout, std::chrono::seconds(5));

    /// Compression method.
    DECLARE_FIELD(compression_method, CompressionMethod, SetCompressionMethod, CompressionMethod::None);

    /// TCP Keep alive options
    DECLARE_FIELD(tcp_keepalive, bool, TcpKeepAlive, false);
    DECLARE_FIELD(tcp_keepalive_idle, std::chrono::seconds, SetTcpKeepAliveIdle, std::chrono::seconds(60));
    DECLARE_FIELD(tcp_keepalive_intvl, std::chrono::seconds, SetTcpKeepAliveInterval, std::chrono::seconds(5));
    DECLARE_FIELD(tcp_keepalive_cnt, unsigned int, SetTcpKeepAliveCount, 3);

    // TCP options
    DECLARE_FIELD(tcp_nodelay, bool, TcpNoDelay, true);

    /** It helps to ease migration of the old codebases, which can't afford to switch
    * to using ColumnLowCardinalityT or ColumnLowCardinality directly,
    * but still want to benefit from smaller on-wire LowCardinality bandwidth footprint.
    *
    * @see LowCardinalitySerializationAdaptor, CreateColumnByType
    */
    DECLARE_FIELD(backward_compatibility_lowcardinality_as_wrapped_column, bool, SetBakcwardCompatibilityFeatureLowCardinalityAsWrappedColumn, true);

#if WITH_OPENSSL
    struct SSLOptions {
        /// If set to true, client will initiate secure connection to the server using OpenSSL.
        bool secure_connection = false;

        /** There are two ways to confiure SSL connection:
         *  - provide a pre-configured SSL_CTX, which is not modified and not owned by the client.
         *  - provide set of options and allow Client to create and configure SSL_CTX by itself.
         */

        /** Pre-configured SSL-context for SSL-connection.
         *  If NOT null client DONES NOT take ownership of context and it must be valid for client lifetime.
         *  If null client initlaizes OpenSSL and creates his own context, initializes it using
         *  other options, like path_to_ca_files, path_to_ca_directory, use_default_ca_locations, etc.
         */
        SSL_CTX * ssl_context = nullptr;

        /** Means to validate server-supplied certificate agains trusted Certificate Authority (CA).
         *  If no CA are configured the server's identity can't be validated and client would err.
         *  See https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_default_verify_paths.html
        */
        /// Load deafult CA certificates from deafult locations.
        bool use_default_ca_locations = true;
        /// Path to the CA files to verify server certificate, may be empty.
        std::vector<std::string> path_to_ca_files = {};
        /// Path to the directory with CA files used to validate server certificate, may be empty.
        std::string path_to_ca_directory = "";

        /** Min and max protocol versions to use, set with SSL_CTX_set_min_proto_version and SSL_CTX_set_max_proto_version
         *  for details see https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_min_proto_version.html
         */
        int min_protocol_version = DEFAULT_VALUE;
        int max_protocol_version = DEFAULT_VALUE;

        /** Options to be set with SSL_CTX_set_options,
         * for details see https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_options.html
        */
        int context_options = DEFAULT_VALUE;

        /** Use SNI at ClientHello and verify that certificate is issued to the hostname we are trying to connect to
         */
        bool use_SNI = true;

        /// Deafult safe value for any of the options above, exact value is secure enough and
        static const int DEFAULT_VALUE = -1;
    };
    DECLARE_FIELD(ssl_options, SSLOptions, SetSSLOptions, {});
#endif

#undef DECLARE_FIELD
};

std::ostream& operator<<(std::ostream& os, const ClientOptions& options);

/**
 *
 */
class Client {
public:
     Client(const ClientOptions& opts);
    ~Client();

    /// Intends for execute arbitrary queries.
    void Execute(const Query& query);

    /// Intends for execute select queries.  Data will be returned with
    /// one or more call of \p cb.
    void Select(const std::string& query, SelectCallback cb);

    /// Executes a select query which can be canceled by returning false from
    /// the data handler function \p cb.
    void SelectCancelable(const std::string& query, SelectCancelableCallback cb);

    /// Alias for Execute.
    void Select(const Query& query);

    /// Intends for insert block of data into a table \p table_name.
    void Insert(const std::string& table_name, const Block& block);

    /// Ping server for aliveness.
    void Ping();

    /// Reset connection with initial params.
    void ResetConnection();

    const ServerInfo& GetServerInfo() const;

private:
    const ClientOptions options_;

    class Impl;
    std::unique_ptr<Impl> impl_;
};

}
