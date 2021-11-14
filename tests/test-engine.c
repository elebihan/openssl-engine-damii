/*
 * This file is part of openssl-engine-damii
 *
 * Copyright (C) 2021 Eric Le Bihan <eric.le.bihan.dev@free.fr>
 *
 * SPDX-License-Identifier: MIT
 */

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <check.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <stdbool.h>
#include <stdlib.h>

#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "engine.h"

#define TEST_CIPHER_PLAIN_FILE "test.plain.txt"
#define TEST_CIPHER_CIPHERED_FILE "test.enc.aes_256_cbc.bin"
#define TEST_RSA_PRIVATE_KEY "RSA-KEY-01"
#define TEST_RSA_PLAIN_FILE "test.rsa.plain.bin"
#define TEST_RSA_ENCRYPTED_FILE "test.rsa.enc.bin"
#define TEST_SIGN_PLAIN_FILE "test.needpadding.plain.txt"
#define TEST_SIGN_SIG_FILE "test.needpadding.plain.txt.rsa"

/* clang-format off */
static const unsigned char test_cipher_key[] = {
	0x41, 0x45, 0x53, 0x2d, 0x4b, 0x45, 0x59,
	0x2d, 0x30, 0x31,
};
static const unsigned char test_cipher_iv[] = {
	0x41, 0x45, 0x53, 0x2d, 0x4b, 0x45, 0x59,
	0x2d, 0x30, 0x31,
};
/* clang-format on */

static char *test_data_dir = NULL;
static char *openssl_cnf = NULL;

int slurp(const char *path, void **data, size_t *length)
{
	int fd = 0;
	struct stat stats;
	ssize_t n_rd = 0;
	int err = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s", path, strerror(fd));
		return -errno;
	}

	err = fstat(fd, &stats);
	if (err < 0) {
		fprintf(stderr, "Failed to get stats for %s: %s", path, strerror(err));
		goto out;
	}

	*data = malloc(stats.st_size);
	if (*data != NULL) {
		n_rd = read(fd, *data, stats.st_size);
		if ((n_rd < 0) || (n_rd < stats.st_size)) {
			fprintf(stderr, "Failed to read %s", path);
			free(*data);
			err = -errno;
		} else {
			*length = stats.st_size;
		}
	}

out:
	close(fd);
	return err;
}

static void slurp_or_die(const char *filename, void **data, size_t *length, const char *msg)
{
	static char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", test_data_dir, filename);

	if (slurp(path, data, length)) {
		ck_abort_msg(msg);
	}
}

static void alloc_or_die(size_t count, void **data, const char *msg)
{
	*data = malloc(count);
	if (*data == NULL) {
		ck_abort_msg("Failed to allocate output");
	}
}

static void init_engine_or_die(ENGINE **e, const char *msg)
{
	*e = ENGINE_by_id(OPENSSL_ENGINE_DAMII_ID);

	if (!ENGINE_init(*e)) {
		ck_abort_msg(msg);
	}
}

static void sha256sum_or_die(void *data, size_t length, void **hash, const char *msg)
{
	SHA256_CTX sha256;

	alloc_or_die(256, hash, "Failed to allocate memeory for hash");

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, data, length);
	SHA256_Final(*hash, &sha256);
}

void test_cipher_aes_256_cbc(const char *tst_path, const char *ref_path, bool encrypt)
{
	ENGINE *e = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	int ret = 0;
	BIO *out = NULL;
	BIO *cipher = NULL;
	BIO *buffer = NULL;
	size_t n_wr = 0;
	unsigned char *tst_data = NULL;
	size_t tst_sz = 0;
	unsigned char *ref_data = NULL;
	size_t ref_sz = 0;
	unsigned char *res_data = NULL;
	size_t res_sz = 0;

	init_engine_or_die(&e, "Failed to init engine");

	if (!ENGINE_set_default_ciphers(e)) {
		ck_abort_msg("Failed to set default ciphers");
	}

	slurp_or_die(tst_path, (void **)&tst_data, &tst_sz, "Failed to read test data");
	slurp_or_die(ref_path, (void **)&ref_data, &ref_sz, "Failed to read reference data");

	fprintf(stderr, "Read %zu bytes for test data\n", tst_sz);
	fprintf(stderr, "Read %zu bytes for reference data\n", ref_sz);

	out = BIO_new(BIO_s_mem());
	buffer = BIO_new(BIO_f_buffer());
	cipher = BIO_new(BIO_f_cipher());

	BIO_get_cipher_ctx(cipher, &ctx);
	ret = EVP_CipherInit_ex(ctx,
				EVP_get_cipherbyname("aes-256-cbc"),
				e,
				(unsigned char *)test_cipher_key,
				(unsigned char *)test_cipher_iv,
				encrypt ? 1 : 0);
	ck_assert_int_ne(ret, 0);

	BIO_push(cipher, buffer);
	BIO_push(buffer, out);

	ret = BIO_write_ex(cipher, tst_data, tst_sz, &n_wr);
	BIO_flush(cipher);
	ck_assert_int_eq(BIO_get_cipher_status(cipher), 1);
	ck_assert_int_eq(ret, 1);

	res_sz = BIO_get_mem_data(out, &res_data);

	ck_assert_int_eq(ref_sz, res_sz);

	ret = memcmp(ref_data, res_data, ref_sz);
	ck_assert_int_eq(ret, 0);

	BIO_free_all(cipher);

	free(tst_data);
	free(ref_data);

	ENGINE_finish(e);
	ENGINE_free(e);
}

static void test_rsa(const char *tst_path, const char *ref_path, bool encrypt)
{
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	ENGINE *e = NULL;
	int ret = 0;
	unsigned char *tst_data = NULL;
	size_t tst_sz = 0;
	unsigned char *ref_data = NULL;
	size_t ref_sz = 0;
	unsigned char *res_data = NULL;
	size_t res_sz = 0;

	init_engine_or_die(&e, "Failed to init engine");
	slurp_or_die(tst_path, (void **)&tst_data, &tst_sz, "Failed to read test data");
	slurp_or_die(ref_path, (void **)&ref_data, &ref_sz, "Failed to read reference data");

	fprintf(stderr, "Read %zu bytes for test data\n", tst_sz);
	fprintf(stderr, "Read %zu bytes for reference data\n", ref_sz);

	if (encrypt) {
		pkey = ENGINE_load_public_key(e, TEST_RSA_PRIVATE_KEY, NULL, NULL);
	} else {
		pkey = ENGINE_load_private_key(e, TEST_RSA_PRIVATE_KEY, NULL, NULL);
	}
	ck_assert_ptr_nonnull(pkey);

	rsa = EVP_PKEY_get1_RSA(pkey);
	ck_assert_ptr_nonnull(rsa);

	res_sz = sizeof(unsigned char) * RSA_size(rsa);
	alloc_or_die(res_sz, (void **)&res_data, "Failed to allocate memory for result");

	if (encrypt) {
		ret = RSA_public_encrypt(tst_sz, tst_data, res_data, rsa, RSA_NO_PADDING);
	} else {
		ret = RSA_private_decrypt(tst_sz, tst_data, res_data, rsa, RSA_NO_PADDING);
	}

	ck_assert_int_ne(ret, -1);

	res_sz = ret;
	ck_assert(res_sz == ref_sz);

	ret = memcmp(ref_data, res_data, ref_sz);
	ck_assert_int_eq(ret, 0);

	free(tst_data);
	free(ref_data);
	free(res_data);

	EVP_PKEY_free(pkey);
}

static void test_sign(const char *tst_path, const char *ref_path, int sign)
{
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	ENGINE *e = NULL;
	unsigned char *tst_data = NULL;
	size_t tst_sz = 0;
	unsigned char *ref_data = NULL;
	size_t ref_sz = 0;
	unsigned char *res_data = NULL;
	size_t res_sz = 0;
	unsigned char *hash = NULL;
	int ret;

	init_engine_or_die(&e, "Failed to init engine");
	slurp_or_die(tst_path, (void **)&tst_data, &tst_sz, "Failed to read test data");
	slurp_or_die(ref_path, (void **)&ref_data, &ref_sz, "Failed to read reference data");

	pkey = ENGINE_load_private_key(e, TEST_RSA_PRIVATE_KEY, NULL, NULL);
	ck_assert_ptr_nonnull(pkey);

	rsa = EVP_PKEY_get1_RSA(pkey);
	ck_assert_ptr_nonnull(rsa);

	sha256sum_or_die(tst_data, tst_sz, (void **)&hash, "Failed to hash test data");

	res_sz = sizeof(unsigned char) * RSA_size(rsa);
	alloc_or_die(res_sz, (void **)&res_data, "Failed to allocate memory for result");

	if (sign) {
		ret = RSA_sign(NID_sha256, hash, 32, res_data, (unsigned int*)&res_sz, rsa);
	} else {
		ret = RSA_verify(NID_sha256, hash, 32, ref_data, ref_sz, rsa);
	}

	ck_assert_int_eq(ret, 1);

	free(hash);
	free(tst_data);
	free(ref_data);
	free(res_data);

	EVP_PKEY_free(pkey);
}

void setup(void)
{
	int rc = 0;

	OPENSSL_load_builtin_modules();
	ENGINE_load_builtin_engines();

	rc = CONF_modules_load_file(openssl_cnf, "test", CONF_MFLAGS_DEFAULT_SECTION);
	if (rc <= 0) {
		fprintf(stderr, "Failed to load configuration\n");
		ERR_print_errors_fp(stderr);
	} else {
		ENGINE_add_conf_module();
	}
}

void teardown(void)
{
	CONF_modules_unload(1);
}

START_TEST(test_engine_is_available)
{
	ENGINE *e = ENGINE_get_first();
	bool available = false;

	while (e != NULL) {
		if (!strcmp(ENGINE_get_id(e), OPENSSL_ENGINE_DAMII_ID)) {
			available = true;
			break;
		}
		e = ENGINE_get_next(e);
	}

	ck_assert(available == true);
}
END_TEST

START_TEST(test_engine_has_aes_256_cbc)
{
	ENGINE *e = NULL;

	e = ENGINE_by_id(OPENSSL_ENGINE_DAMII_ID);

	ck_assert_ptr_nonnull(ENGINE_get_cipher(e, NID_aes_256_cbc));
}
END_TEST

START_TEST(test_engine_can_encrypt_aes_256_cbc)
{
	test_cipher_aes_256_cbc(TEST_CIPHER_PLAIN_FILE, TEST_CIPHER_CIPHERED_FILE, true);
}
END_TEST

START_TEST(test_engine_can_decrypt_aes_256_cbc)
{
	test_cipher_aes_256_cbc(TEST_CIPHER_CIPHERED_FILE, TEST_CIPHER_PLAIN_FILE, false);
}
END_TEST

START_TEST(test_engine_can_encrypt_rsa)
{
	test_rsa(TEST_RSA_PLAIN_FILE, TEST_RSA_ENCRYPTED_FILE, true);
}
END_TEST

START_TEST(test_engine_can_decrypt_rsa)
{
	test_rsa(TEST_RSA_ENCRYPTED_FILE, TEST_RSA_PLAIN_FILE, false);
}
END_TEST

START_TEST(test_engine_can_sign_rsa)
{
	test_sign(TEST_SIGN_PLAIN_FILE, TEST_SIGN_SIG_FILE, true);
}
END_TEST

START_TEST(test_engine_can_verify_rsa)
{
	test_sign(TEST_SIGN_PLAIN_FILE, TEST_SIGN_SIG_FILE, false);
}
END_TEST

Suite *engine_suite(void)
{
	Suite *s = NULL;
	TCase *tc_init = NULL;
	TCase *tc_cipher = NULL;
	TCase *tc_rsa = NULL;

	s = suite_create("DAMII");

	tc_init = tcase_create("Initialization");
	tcase_add_checked_fixture(tc_init, setup, teardown);
	tcase_add_test(tc_init, test_engine_is_available);
	suite_add_tcase(s, tc_init);

	tc_cipher = tcase_create("Cipher");
	tcase_add_checked_fixture(tc_cipher, setup, teardown);
	tcase_add_test(tc_cipher, test_engine_has_aes_256_cbc);
	tcase_add_test(tc_cipher, test_engine_can_encrypt_aes_256_cbc);
	tcase_add_test(tc_cipher, test_engine_can_decrypt_aes_256_cbc);
	suite_add_tcase(s, tc_cipher);

	tc_rsa = tcase_create("RSA");
	tcase_add_checked_fixture(tc_rsa, setup, teardown);
	tcase_add_test(tc_rsa, test_engine_can_decrypt_rsa);
	tcase_add_test(tc_rsa, test_engine_can_encrypt_rsa);
	tcase_add_test(tc_rsa, test_engine_can_sign_rsa);
	tcase_add_test(tc_rsa, test_engine_can_verify_rsa);
	suite_add_tcase(s, tc_rsa);

	return s;
}

int main(int argc, char *argv[])
{
	int n_failed = 0;
	Suite *s = NULL;
	SRunner *sr = NULL;

	if (argc != 3) {
		fprintf(stderr, "Missing OpenSSL configuration file\n");
		return EXIT_FAILURE;
	}

	openssl_cnf = argv[1];
	test_data_dir = argv[2];

	s = engine_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	n_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (n_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
