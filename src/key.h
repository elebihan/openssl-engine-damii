/*
 * This file is part of openssl-engine-damii
 *
 * Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KEY_H
#define KEY_H

#include <stdint.h>

#define AES_KEY_256_BYTE_SZ 256
#define AES_BLOCK_BYTE_SZ 16
#define AES_KEY_MAX_BYTE_SZ AES_KEY_256_BYTE_SZ
#define RSA_KEY_MAX_BYTE_SZ (4 * 1024)

typedef struct _DAMII_AES_KEY {
	uint8_t key[AES_KEY_MAX_BYTE_SZ];
	uint16_t key_sz;
	uint8_t iv[AES_BLOCK_BYTE_SZ];
	uint8_t iv_sz;
} DAMII_AES_KEY;

typedef struct _DAMII_RSA_KEY {
	uint8_t key[RSA_KEY_MAX_BYTE_SZ];
	uint16_t key_sz;
} DAMII_RSA_KEY;

typedef union _DAMII_KEY {
	DAMII_AES_KEY aes_key;
	DAMII_RSA_KEY rsa_key;
} DAMII_KEY;

typedef enum _DAMII_KEY_KIND {
	DAMII_KEY_KIND_AES,
	DAMII_KEY_KIND_RSA,
} DAMII_KEY_KIND;

typedef struct _DAMII_KEYRING_ENTRY {
	const char *label;
	DAMII_KEY_KIND key_kind;
	DAMII_KEY key;
} DAMII_KEYRING_ENTRY;

#endif /* KEY_H */
