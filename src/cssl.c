//
// Created by mawe on 8/11/25.
//

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/syslog.h>

SSL_CTX* initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

SSL_CTX* ssl_ctx_init(const char* cert_location, const char* key_location) {
    SSL_CTX* ctx = initialize_openssl();
    if (ctx == NULL) {
        syslog(LOG_ERR, "Failed to initialize OpenSSL");
        return NULL; // TODO: FATAL
    }
    if (SSL_CTX_use_certificate_file(ctx, cert_location, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_location, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void ssl_cleanup(SSL_CTX* ctx) {
    // SSL cleanup
    SSL_CTX_free(ctx);
    EVP_cleanup();
}
