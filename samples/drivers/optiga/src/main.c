/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include "ifx_optiga_trust_m.h"

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);
struct device *dev = NULL;

/* APDU buffer for the command library */
static u8_t apdu_buf[OPTRUST_MAX_APDU_SIZE] = {0};

/* Buffer for the device certificate of the OPTIGA */
#define CERT_BUFFER_LEN 1024
static u8_t cert_buf[CERT_BUFFER_LEN] = {0};
size_t cert_len = CERT_BUFFER_LEN;

#define DIGEST_LEN 32

// set to '1' to run additional tests
#define RUN_TESTS 0

// set to '1' to run shielded connection tests
#define SC_TEST 1

void main(void)
{
	LOG_INF("Hello OPTIGA");
	dev = device_get_binding("trust-m");

	if (dev == NULL) {
		LOG_INF("Could not get Trust M device\n");
		return;
	}

	LOG_INF("Found Trust M device");

#if RUN_TESTS == 1
	run_tests();
	return;
#endif

	struct optrust_ctx ctx;

	s64_t time_stamp = k_uptime_get();
	/* Initialize the command library */
	int res = optrust_init(&ctx, dev, apdu_buf, OPTRUST_MAX_APDU_SIZE);
	s32_t milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_trust_init res: %d, took %d ms", res, milliseconds_spent);
#if SC_TEST == 1

	static const u8_t psk[64] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
	};

	time_stamp = k_uptime_get();
	res = optrust_data_set(&ctx, 0xE140, true, 0, psk, 64);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("set platform binding secret res: %d, took %d ms", res, milliseconds_spent);

	res = optrust_shielded_connection_psk_start(&ctx, psk, 64);
	LOG_INF("optrust_shielded_connection_psk_start res: %d, took %d ms", res, 0);

	/* read co-processor UID */
	cert_len = CERT_BUFFER_LEN;

	time_stamp = k_uptime_get();
	res = optrust_data_get(&ctx, 0xE0C2, 0, cert_buf, &cert_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_data_get res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(cert_buf, cert_len, "Co-processor UID:");

#endif

	/* read device certificate */
	cert_len = CERT_BUFFER_LEN;

	time_stamp = k_uptime_get();
	res = optrust_data_get(&ctx, 0xE0E0, 0, cert_buf, &cert_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_data_get res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(cert_buf, cert_len, "Full Certificate:");


	k_sleep(100);

	/* Write the stripped device certificate to another data object */
	time_stamp = k_uptime_get();
	res = optrust_data_set(&ctx, 0xE0E1, true, 0, cert_buf + 9, cert_len - 9);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_data_set res: %d, took %d ms", res, milliseconds_spent);
	k_sleep(100);

	/* Read the stripped device certificate */
	cert_len = CERT_BUFFER_LEN;
	time_stamp = k_uptime_get();
	res = optrust_data_get(&ctx, 0xE0E1, 0, cert_buf, &cert_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_data_get res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(cert_buf, cert_len, "Stripped Certificate:");

	u8_t digest[DIGEST_LEN] = {0};
	u8_t signature[OPTRUST_NIST_P256_SIGNATURE_LEN] = {0};
	size_t signature_len = OPTRUST_NIST_P256_SIGNATURE_LEN;

	time_stamp = k_uptime_get();

	/* Use the device key to create a signature */
	res = optrust_ecdsa_sign_oid(&ctx, 0xE0F0, digest, DIGEST_LEN,
		signature, &signature_len);

	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_ecdsa_sign_oid res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(signature, OPTRUST_NIST_P256_SIGNATURE_LEN, "Signature:");

	k_sleep(100);

	time_stamp = k_uptime_get();

	/* Verify the signature using the stripped certificate */
	res = optrust_ecdsa_verify_oid(&ctx, 0xE0E1, digest, DIGEST_LEN,
		signature, OPTRUST_NIST_P256_SIGNATURE_LEN);

	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_ecdsa_verify_oid res: %d, took %d ms", res, milliseconds_spent);
	LOG_INF("VERIFY: %s", res == 0 ? "PASS" : "FAIL");

	u8_t pub_key[OPTRUST_NIST_P256_PUB_KEY_LEN] = {0};
	size_t pub_key_len = OPTRUST_NIST_P256_PUB_KEY_LEN;

	/* Acquire session context */
	u16_t priv_key_oid = 0;
	res = optrust_session_acquire(&ctx, &priv_key_oid);
	if (res != 0) {
		LOG_ERR("Failed to request session context");
		return;
	}

	time_stamp = k_uptime_get();

	/* Generate an ECC keypair and export the public key */
	res = optrust_ecc_gen_keys_oid(&ctx, priv_key_oid, OPTRUST_ALGORITHM_NIST_P256,
		OPTRUST_KEY_USAGE_FLAG_SIGN | OPTRUST_KEY_USAGE_FLAG_KEY_AGREE, pub_key, &pub_key_len);

	milliseconds_spent = k_uptime_delta(&time_stamp);
	LOG_INF("ifx_optiga_trust_gen_key_ecdsa res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(pub_key, OPTRUST_NIST_P256_PUB_KEY_LEN, "Public key:");

	u8_t hash_buf[OPTRUST_SHA256_DIGEST_LEN] = {0};
	size_t hash_buf_len = OPTRUST_SHA256_DIGEST_LEN;

#if 0
	/* Acquire session context to force Hibernation */
	u16_t oid = 0;
	res = optrust_session_acquire(&ctx, &oid);
	LOG_INF("optrust_session_acquire res: %d", res);

	/* Wait a second so OPTIGA goes to sleep */
	k_sleep(11000);

	time_stamp = k_uptime_get();

	/* Hash some data */
	res = optrust_sha256_oid(&ctx,  0xE0E1, 0, 32, hash_buf, &hash_buf_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_hash_sha256_oid res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(hash_buf, OPTRUST_SHA256_DIGEST_LEN, "Hash:");

	/* Release session to do full shutdown again */
	res = optrust_session_release(&ctx, oid);
	LOG_INF("optrust_session_release res: %d", res);

	int wake_token;
	res = optrust_wake_lock_acquire(&ctx, &wake_token);
	LOG_INF("optrust_wake_lock_acquire res: %d", res);
	k_sleep(10000);

	optrust_wake_lock_release(&ctx, wake_token);
#endif

	u8_t test_digest[OPTRUST_SHA256_DIGEST_LEN] = {0};
	size_t test_digest_len = OPTRUST_SHA256_DIGEST_LEN;

	time_stamp = k_uptime_get();

	/* Hash some data */
	res = optrust_sha256_ext(&ctx, psk, 64, test_digest, &test_digest_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("optrust_sha256_ext res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(test_digest, test_digest_len, "Hash: ");



	u8_t sec_key[OPTRUST_NIST_P256_SEC_KEY_LEN] = {0};
	size_t sec_key_len = OPTRUST_NIST_P256_SEC_KEY_LEN;
	pub_key_len = OPTRUST_NIST_P256_PUB_KEY_LEN;

	time_stamp = k_uptime_get();

	/* Generate ECC key pair */
	res = optrust_ecc_gen_keys_ext(&ctx, OPTRUST_ALGORITHM_NIST_P256, sec_key, &sec_key_len, pub_key, &pub_key_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("optrust_ecc_gen_keys_ext res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(sec_key, sec_key_len, "Secret key: ");
	LOG_HEXDUMP_INF(pub_key, pub_key_len, "Public key: ");

	/* Verify signature external key */
	// Signature verification key
	static const uint8_t verify_test_key[OPTRUST_NIST_P256_PUB_KEY_LEN] = {
		0xD0, 0x17, 0x5E, 0xF0, 0xE0, 0x04, 0x7F, 0xC7, 0x57, 0xE3, 0x38, 0x82, 0xEA, 0x90, 0xDB, 0xFC,
		0xD4, 0x73, 0x7D, 0x7C, 0xC4, 0xE7, 0x48, 0x95, 0xC7, 0x18, 0xC2, 0xD1, 0x7D, 0x84, 0x33, 0x33,
		0x50, 0x27, 0x70, 0xCC, 0xA7, 0x56, 0x75, 0x88, 0x6E, 0xF4, 0x3C, 0x7A, 0x13, 0x93, 0xAB, 0x58,
		0xB8, 0x54, 0xD5, 0x02, 0xD9, 0xB0, 0x6D, 0xF2, 0x2A, 0x24, 0x1D, 0xEF, 0xC9, 0x10, 0x5A, 0xFB
	};

	static const uint8_t test_signature[OPTRUST_NIST_P256_SIGNATURE_LEN] = {
		// R bytes
		0x8C, 0x73, 0x3C, 0xA6, 0xE9, 0x5F, 0xD5, 0xF9, 0x59, 0x2E, 0x75, 0xC6, 0x3D, 0x05, 0x88, 0x55,
		0x89, 0x9B, 0x31, 0x64, 0x96, 0x9F, 0x20, 0x63, 0xF5, 0x55, 0xA6, 0x40, 0x1D, 0x5E, 0xCA, 0x06,
		// S bytes
		0x33, 0x92, 0x29, 0x31, 0xB3, 0x48, 0xAC, 0x57, 0x25, 0x60, 0xA3, 0x49, 0xB4, 0xC8, 0xCF, 0xCA,
		0xC6, 0x89, 0x3E, 0x2B, 0xD1, 0xE8, 0x38, 0x36, 0x55, 0x3C, 0x17, 0xC3, 0xA2, 0xEB, 0x6C, 0x2F
	};

	static const uint8_t test_hash[OPTRUST_SHA256_DIGEST_LEN] = {
		0x7F, 0x83, 0xB1, 0x65, 0x7F, 0xF1, 0xFC, 0x53, 0xB9, 0x2D, 0xC1, 0x81, 0x48, 0xA1, 0xD6, 0x5D,
		0xFC, 0x2D, 0x4B, 0x1F, 0xA3, 0xD6, 0x77, 0x28, 0x4A, 0xDD, 0xD2, 0x00, 0x12, 0x6D, 0x90, 0x69
	};

	time_stamp = k_uptime_get();

	/* Generate ECC key pair */
	res = optrust_ecdsa_verify_ext(&ctx, OPTRUST_ALGORITHM_NIST_P256,
					verify_test_key, OPTRUST_NIST_P256_PUB_KEY_LEN,
					test_hash, OPTRUST_SHA256_DIGEST_LEN,
					test_signature, OPTRUST_NIST_P256_SIGNATURE_LEN);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("optrust_ecc_verify_ext res: %d, took %d ms", res, milliseconds_spent);


	time_stamp = k_uptime_get();

// TODO(chr): find out why two consecutive shared secret calculations fail
#if 0
	/* Generate Shared Secret key pair and export to host */
	u8_t shared_secret[64] = {0};
	size_t shared_secret_len = 64;
	time_stamp = k_uptime_get();
	res = optrust_ecdh_calc_ext(&ctx,
					priv_key_oid,
					OPTRUST_ALGORITHM_NIST_P256,
					verify_test_key, OPTRUST_NIST_P256_PUB_KEY_LEN,
					shared_secret, &shared_secret_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("optrust_ecdh_calc_ext res: %d, took %d ms", res, milliseconds_spent);

#endif

	/* Acquire temporary session context */
	u16_t tmp_oid = 0;
	res = optrust_session_acquire(&ctx, &tmp_oid);
	if (res != 0) {
		LOG_ERR("Failed to request session context");
		return;
	}

	/* Generate Shared Secret key pair and store in OID */
	res = optrust_ecdh_calc_oid(&ctx,
					priv_key_oid,
					OPTRUST_ALGORITHM_NIST_P256,
					verify_test_key, OPTRUST_NIST_P256_PUB_KEY_LEN,
					tmp_oid);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("optrust_ecdh_calc_oid res: %d, took %d ms", res, milliseconds_spent);

	/* Release temporary session context again */
	res = optrust_session_release(&ctx, tmp_oid);

	/* Get some random data */
	cert_len = 8;

	time_stamp = k_uptime_get();
	res = optrust_rng_gen_ext(&ctx, OPTRUST_RNG_TYPE_TRNG, cert_buf, cert_len);
	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_HEXDUMP_INF(cert_buf, cert_len, "Random data: ");



	LOG_INF("Example finished");
}
