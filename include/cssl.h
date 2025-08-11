//
// Created by mawe on 8/11/25.
//

#ifndef CSSL_H
#define CSSL_H
#include <openssl/types.h>

SSL_CTX* ssl_ctx_init();
void ssl_cleanup(SSL_CTX* ctx);

#endif //CSSL_H
