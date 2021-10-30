/*
 * This file is part of openssl-engine-damii
 *
 * Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OPENSSL_ENGINE_DAMII_H
#define OPENSSL_ENGINE_DAMII_H

#include <openssl/engine.h>

/**
 * @file openssl-engine-damii.h
 * @brief API for openssl-engine-damii
 */

/**
 * @mainpage
 *
 * OpenSSL engine example, using hard-coded keys.
 */

#define OPENSSL_ENGINE_DAMII_ID "damii"
#define OPENSSL_ENGINE_DAMII_NAME "Dummy engine with hard-coded keys"

#define CMD_SET_VAULT_PATH ENGINE_CMD_BASE

#endif /* OPENSSL_ENGINE_DAMII_H */
