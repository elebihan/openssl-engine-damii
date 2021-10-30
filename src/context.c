/*
 * This file is part of openssl-engine-damii
 *
 * Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
 *
 * SPDX-License-Identifier: MIT
 */

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

#include "context.h"
#include "key.h"
#include "keys.h"

#define AES_KEY_256_BYTE_SZ 256
#define AES_BLOCK_BYTE_SZ 16
#define AES_KEY_MAX_BYTE_SZ AES_KEY_256_BYTE_SZ
#define RSA_KEY_MAX_BYTE_SZ (4 * 1024)

struct _DAMII_CTX {
	DAMII_KEYRING_ENTRY *keys;
	size_t n_keys;
	size_t key_idx;
	int encrypt;
};

int ctx_init(DAMII_CTX *ctx)
{
	return 1;
}

int ctx_finish(DAMII_CTX *ctx)
{
	return 1;
}

int ctx_destroy(DAMII_CTX *ctx)
{
	if (ctx != NULL) {
		OPENSSL_free(ctx);
	}

	return 1;
}

static inline int ctx_load_keys(DAMII_CTX *ctx)
{
	ctx->keys = keys;
	ctx->n_keys = sizeof(keys) / sizeof(keys[0]);
	ctx->key_idx = 0;

	return 1;
}

DAMII_CTX *ctx_new(void)
{
	DAMII_CTX *ctx = NULL;
	int ret = 0;

	ctx = OPENSSL_malloc(sizeof(DAMII_CTX));
	if (ctx == NULL) {
		return NULL;
	}

	ret = ctx_load_keys(ctx);
	if (ret == 0) {
		ctx_destroy(ctx);
		ctx = NULL;
	}

	return ctx;
}

size_t ctx_get_keys_count(DAMII_CTX *ctx)
{
	return (ctx != NULL) ? ctx->n_keys : 0;
}

int ctx_select_key(DAMII_CTX *ctx, const char *label)
{
	if (ctx == NULL) {
		return 0;
	}

	for (size_t i = 0; i < ctx->n_keys; i++) {
		if (!strcmp(ctx->keys[i].label, label)) {
			ctx->key_idx = i;
			fprintf(stderr, "DEBUG: using key %zu\n", i);
			return 1;
		}
	}

	return 0;
}

static EVP_PKEY *ctx_make_rsa_key(DAMII_CTX *ctx, int pub)
{
	DAMII_RSA_KEY *rsa_key = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	RSA *tmp = NULL;
	BIO *in = NULL;
	int ret = 0;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		return NULL;
	}

	rsa_key = &ctx->keys[ctx->key_idx].key.rsa_key;
	in = BIO_new_mem_buf(rsa_key->key, rsa_key->key_sz);
	if (in == NULL) {
		goto error;
	}

	rsa = PEM_read_bio_RSAPrivateKey(in, &rsa, NULL, NULL);
	if (rsa == NULL) {
		goto error;
	}

	if (pub) {
		tmp = RSAPublicKey_dup(rsa);
		RSA_free(rsa);
		if (tmp == NULL) {
			goto error;
		} else {
			rsa = tmp;
		}
	}

	ret = EVP_PKEY_assign_RSA(pkey, rsa);
	if (ret == 0) {
		RSA_free(rsa);
		goto error;
	}

	ret = RSA_set_app_data(rsa, ctx);
	if (ret == 0) {
		goto error;
	}

	return pkey;

error:
	EVP_PKEY_free(pkey);
	return NULL;
}

static EVP_PKEY *ctx_load_key(DAMII_CTX *ctx, const char *key_id, int pub)
{
	EVP_PKEY *pkey = NULL;
	int ret = 0;

	ret = ctx_select_key(ctx, key_id);
	if (ret == 1) {
		pkey = ctx_make_rsa_key(ctx, pub);
	}

	return pkey;
}

EVP_PKEY *
ctx_load_pubkey(DAMII_CTX *ctx, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
	return ctx_load_key(ctx, key_id, 1);
}

EVP_PKEY *
ctx_load_privkey(DAMII_CTX *ctx, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
	return ctx_load_key(ctx, key_id, 0);
}

int ctx_aes_cbc_init(DAMII_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	ctx->encrypt = enc;
	return ctx_select_key(ctx, (const char *)key);
}

int ctx_aes_cbc_do_cipher(DAMII_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_sz)
{
	DAMII_AES_KEY *aes_key = NULL;
	symmetric_CBC mode;
	int cipher = 0;
	int ret = 0;

	aes_key = &ctx->keys[ctx->key_idx].key.aes_key;

	register_cipher(&aes_desc);

	cipher = find_cipher("aes");
	if (cipher == -1) {
		fprintf(stderr, "Failed to find cipher\n");
		return -1;
	}

	ret = cbc_start(cipher, aes_key->iv, aes_key->key, aes_key->key_sz, 0, &mode);
	if (ret != CRYPT_OK) {
		fprintf(stderr, "Failed to start ciphering\n");
		return -2;
	}

	if (ctx->encrypt) {
		ret = cbc_encrypt(in, out, in_sz, &mode);
	} else {
		ret = cbc_decrypt(in, out, in_sz, &mode);
	}

	if (ret != CRYPT_OK) {
		fprintf(stderr, "Failed to %s\n", ctx->encrypt ? "encrypt" : "decrypt");
		ret = -3;
	} else {
		ret = 1;
	}

	cbc_done(&mode);

	return ret;
}

int ctx_aes_cbc_cleanup(DAMII_CTX *ctx)
{
	return 0;
}
