/*
 * This file is part of openssl-engine-damii
 *
 * Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CONTEXT_H
#define CONTEXT_H

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
typedef struct _DAMII_CTX DAMII_CTX;

int ctx_init(DAMII_CTX *ctx);
int ctx_finish(DAMII_CTX *ctx);
DAMII_CTX *ctx_new(void);
int ctx_destroy(DAMII_CTX *ctx);
EVP_PKEY *
ctx_load_pubkey(DAMII_CTX *ctx, const char *s_key_id, UI_METHOD *ui_method, void *callback_data);
EVP_PKEY *
ctx_load_privkey(DAMII_CTX *ctx, const char *s_key_id, UI_METHOD *ui_method, void *callback_data);
int ctx_aes_cbc_init(DAMII_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int ctx_aes_cbc_do_cipher(DAMII_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_sz);
int ctx_aes_cbc_cleanup(DAMII_CTX *ctx);
size_t ctx_get_keys_count(DAMII_CTX *ctx);

#endif /* CONTEXT_H */
