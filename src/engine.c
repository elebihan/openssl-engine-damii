/*
 * This file is part of openssl-engine-damii
 *
 * Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
 *
 * SPDX-License-Identifier: MIT
 */

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <stdbool.h>
#include <stdio.h>

#include "engine.h"
#include "context.h"

static const char *engine_id = OPENSSL_ENGINE_DAMII_ID;
static const char *engine_name = OPENSSL_ENGINE_DAMII_NAME;

static int damii_idx = -1;

static DAMII_CTX *ctx_for_engine(ENGINE *e)
{
	DAMII_CTX *ctx = NULL;

	if (damii_idx < 0) {
		damii_idx = ENGINE_get_ex_new_index(0, "damii", NULL, NULL, NULL);
		if (damii_idx < 0) {
			return NULL;
		}
	} else {
		ctx = ENGINE_get_ex_data(e, damii_idx);
	}

	if (ctx == NULL) {
		ctx = ctx_new();
		ENGINE_set_ex_data(e, damii_idx, ctx);
	}

	return ctx;
}

/* clang-format off */
static const ENGINE_CMD_DEFN engine_cmd_defns[] = {
	{ CMD_SET_VAULT_PATH,
	  "SET_VAULT_PATH",
	  "Specifies the path to vault file",
	  ENGINE_CMD_FLAG_STRING },
	{ 0, NULL, NULL, 0 }
};
/* clang-format on */

static DAMII_CTX *ctx_for_cipher(EVP_CIPHER_CTX *ctx)
{
	int nid = EVP_CIPHER_CTX_nid(ctx);
	ENGINE *e = ENGINE_get_cipher_engine(nid);
	return ctx_for_engine(e);
}

static int
engine_aes_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	return ctx_aes_cbc_init(ctx_for_cipher(ctx), key, iv, enc);
}

static inline int engine_aes_cbc_do_cipher(EVP_CIPHER_CTX *ctx,
					   unsigned char *out,
					   const unsigned char *in,
					   size_t inlen)
{
	return ctx_aes_cbc_do_cipher(ctx_for_cipher(ctx), out, in, inlen);
}

static int engine_aes_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
	return ctx_aes_cbc_cleanup(ctx_for_cipher(ctx));
}

static EVP_CIPHER *engine_aes_256_cbc_cipher = NULL;
static const EVP_CIPHER *engine_aes_256_cbc(void)
{
	EVP_CIPHER *cipher = NULL;

	if (engine_aes_256_cbc_cipher != NULL) {
		return engine_aes_256_cbc_cipher;
	}

	cipher = EVP_CIPHER_meth_new(NID_aes_256_cbc, 16, 32);
	if (cipher != NULL) {
		if (!EVP_CIPHER_meth_set_iv_length(cipher, 16) ||
		    !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_CBC_MODE) ||
		    !EVP_CIPHER_meth_set_init(cipher, engine_aes_cbc_init) ||
		    !EVP_CIPHER_meth_set_do_cipher(cipher, engine_aes_cbc_do_cipher) ||
		    !EVP_CIPHER_meth_set_cleanup(cipher, engine_aes_cbc_cleanup) ||
		    !EVP_CIPHER_meth_set_impl_ctx_size(cipher, 0)) {
			EVP_CIPHER_meth_free(cipher);
			cipher = NULL;
		}
	}
	engine_aes_256_cbc_cipher = cipher;

	return engine_aes_256_cbc_cipher;
}

static void engine_aes_256_cbc_destroy(void)
{
	EVP_CIPHER_meth_free(engine_aes_256_cbc_cipher);
	engine_aes_256_cbc_cipher = NULL;
}

static int engine_cipher_nids(const int **nids)
{
	static int cipher_nids[2] = { 0, 0 };
	static int pos = 0;
	static bool init = false;
	const EVP_CIPHER *cipher = NULL;

	if (!init) {
		cipher = engine_aes_256_cbc();
		if (cipher != NULL) {
			cipher_nids[pos++] = EVP_CIPHER_nid(cipher);
		}
		cipher_nids[pos] = 0;
		init = true;
	}
	*nids = cipher_nids;
	return pos;
}

int engine_cipher_select(ENGINE *engine, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	int ret = 0;

	if (cipher == NULL) {
		return engine_cipher_nids(nids);
	}

	switch (nid) {
	case NID_aes_256_cbc:
		*cipher = engine_aes_256_cbc();
		ret = 1;
		break;
	default:
		*cipher = NULL;
		break;
	}

	return ret;
}

static EVP_PKEY *
engine_load_pubkey(ENGINE *engine, const char *s_key_id, UI_METHOD *ui_method, void *callback_data)
{
	DAMII_CTX *ctx = NULL;

	ctx = ctx_for_engine(engine);
	if (ctx == NULL) {
		return 0;
	}

	return ctx_load_pubkey(ctx, s_key_id, ui_method, callback_data);
}

static EVP_PKEY *
engine_load_privkey(ENGINE *engine, const char *s_key_id, UI_METHOD *ui_method, void *callback_data)
{
	DAMII_CTX *ctx = NULL;

	ctx = ctx_for_engine(engine);
	if (ctx == NULL) {
		return 0;
	}

	return ctx_load_privkey(ctx, s_key_id, ui_method, callback_data);
}

static int engine_ctrl(ENGINE *engine, int cmd, long i, void *p, void (*f)(void))
{
	int rc = 1;

	switch (cmd) {
	case CMD_SET_VAULT_PATH:
		fprintf(stderr, "Vault path is %s\n", (char *)p);
		break;
	default:
		rc = 0;
		break;
	}
	return rc;
}

static int engine_init(ENGINE *engine)
{
	DAMII_CTX *ctx = NULL;

	ctx = ctx_for_engine(engine);
	if (ctx == NULL) {
		return 0;
	}

	return ctx_init(ctx);
}

static int engine_finish(ENGINE *engine)
{
	DAMII_CTX *ctx = NULL;

	ctx = ctx_for_engine(engine);
	if (ctx == NULL) {
		return 0;
	}

	return ctx_finish(ctx);
}

static int engine_destroy(ENGINE *engine)
{
	DAMII_CTX *ctx = NULL;
	int rc = 0;

	ctx = ctx_for_engine(engine);
	if (ctx == NULL) {
		return 0;
	}

	rc = ctx_finish(ctx);
	rc &= ctx_destroy(ctx);
	ENGINE_set_ex_data(engine, damii_idx, NULL);
	engine_aes_256_cbc_destroy();

	return rc;
}

static int bind(ENGINE *engine, const char *id)
{
	if (!ENGINE_set_id(engine, engine_id)) {
		fprintf(stderr, "Failed to set engine ID\n");
		return 0;
	}

	if (!ENGINE_set_name(engine, engine_name)) {
		fprintf(stderr, "Failed to set engine name\n");
		return 0;
	}

	if (!ENGINE_set_cmd_defns(engine, engine_cmd_defns)) {
		fprintf(stderr, "Failed to set engine commands\n");
		return 0;
	}

	if (!ENGINE_set_ctrl_function(engine, engine_ctrl)) {
		fprintf(stderr, "Failed to set engine ctrl function\n");
		return 0;
	}

	if (!ENGINE_set_init_function(engine, engine_init)) {
		fprintf(stderr, "Failed to set engine init function\n");
		return 0;
	}

	if (!ENGINE_set_finish_function(engine, engine_finish)) {
		fprintf(stderr, "Failed to set engine finish function\n");
		return 0;
	}

	if (!ENGINE_set_destroy_function(engine, engine_destroy)) {
		fprintf(stderr, "Failed to set engine destroy function\n");
		return 0;
	}

	if (!ENGINE_set_load_privkey_function(engine, engine_load_privkey)) {
		fprintf(stderr, "Failed to set engine load_privkey function\n");
		return 0;
	}

	if (!ENGINE_set_load_pubkey_function(engine, engine_load_pubkey)) {
		fprintf(stderr, "Failed to set engine load_pubkey function\n");
		return 0;
	}

	if (!ENGINE_set_ciphers(engine, engine_cipher_select)) {
		fprintf(stderr, "Failed to set engine cipher selector\n");
		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
