/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/crypto/optiga_trust_m.h>

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);
struct device *dev = NULL;

/* APDU buffer for the command library */
static u8_t apdu_buf[OPTRUST_CERT_READ_APDU_SIZE] = { 0 };

/* Context for the command library */
static struct optrust_ctx ctx;

static void start_shielded_connection(void)
{
	/* Platform Binding Secret used for this example and testing */
	static const u8_t psk[OPTRUST_SHIELD_PSK_LEN] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
	};

	s64_t start_time = k_uptime_get();

	/*
	 * Set platform binding secret to known value for this example.
	 * In production devices, this would be done in the personalization phase.
	 */
	int res = optrust_data_set(&ctx, OPTRUST_OID_PLATFORM_BINDING_SECRET, true, 0, psk, OPTRUST_SHIELD_PSK_LEN);

	LOG_INF("set platform binding secret res: %d, took %dms", res, (int) k_uptime_delta(&start_time));

	start_time = k_uptime_get();

	/* Start shielded connection */
	res = optrust_shielded_connection_psk_start(&ctx, psk, OPTRUST_SHIELD_PSK_LEN);

	LOG_INF("optrust_shielded_connection_psk_start res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
}

/* A random hash so that we have something to sign */
static const uint8_t test_digest[OPTRUST_SHA256_DIGEST_LEN] = {
	0x7F, 0x83, 0xB1, 0x65, 0x7F, 0xF1, 0xFC, 0x53, 0xB9, 0x2D, 0xC1, 0x81, 0x48, 0xA1, 0xD6, 0x5D,
	0xFC, 0x2D, 0x4B, 0x1F, 0xA3, 0xD6, 0x77, 0x28, 0x4A, 0xDD, 0xD2, 0x00, 0x12, 0x6D, 0x90, 0x69
};

/*
 * In this example, the complete flow of an RSA signature operation is demonstrated.
 * It starts with generating a key pair on the OPTIGA Trust M, continues with the
 * signature operation and finishes with the signature verification.
 */
static void example_rsa()
{
	/* OID to store the secret key */
	const u16_t sec_key_oid = OPTRUST_OID_RSA_KEY_1;
	const enum OPTRUST_KEY_USAGE_FLAG key_usage = OPTRUST_KEY_USAGE_FLAG_SIGN;
	const enum OPTRUST_ALGORITHM key_alg = OPTRUST_ALGORITHM_RSA_2048;
	const enum OPTRUST_SIGNATURE_SCHEME sig_scheme = OPTRUST_SIGNATURE_SCHEME_PKCS1_v1_5_SHA256;

	u8_t pub_key[OPTRUST_RSA2048_PUB_KEY_LEN] = { 0 };
	size_t pub_key_len = OPTRUST_RSA2048_PUB_KEY_LEN;

	LOG_INF("Generating RSA key pair, this might take a few seconds");

	s64_t start_time = k_uptime_get();
	int res = optrust_rsa_gen_keys_oid(&ctx, sec_key_oid, key_alg, key_usage, pub_key, &pub_key_len);

	LOG_INF("optrust_rsa_gen_keys_oid res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_HEXDUMP_INF(pub_key, pub_key_len, "RSA Public Key:");

	/* Sign some data using RSA */

	u8_t signature[OPTRUST_RSA2048_SIGNATURE_LEN] = { 0 };
	size_t signature_len = OPTRUST_RSA2048_SIGNATURE_LEN;

	start_time = k_uptime_get();

	/* Use the device key to create a signature */
	res = optrust_rsa_sign_oid(&ctx, sec_key_oid, sig_scheme,
				   test_digest, OPTRUST_SHA256_DIGEST_LEN,
				   signature, &signature_len);

	LOG_INF("optrust_rsa_sign_oid res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_HEXDUMP_INF(signature, signature_len, "RSA Signature:");

	/* Verify RSA signature */
	start_time = k_uptime_get();

	res = optrust_rsa_verify_ext(&ctx, sig_scheme,
				     key_alg, pub_key, pub_key_len,
				     test_digest, OPTRUST_SHA256_DIGEST_LEN,
				     signature, signature_len);

	LOG_INF("optrust_rsa_verify_ext res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_INF("RSA Verify: %s", res == 0 ? "PASS" : "FAIL");
}

/*
 * In this example, the complete flow of an ECC signature operation is demonstrated.
 * It starts with generating a key pair on the OPTIGA Trust M, continues with the
 * signature operation and finishes with the signature verification.
 */
static void example_ecc()
{
	/* OID to store the secret key, slot 1 is already provisioned */
	const u16_t sec_key_oid = OPTRUST_OID_ECC_KEY_2;
	const enum OPTRUST_KEY_USAGE_FLAG key_usage = OPTRUST_KEY_USAGE_FLAG_SIGN;
	const enum OPTRUST_ALGORITHM key_alg = OPTRUST_ALGORITHM_NIST_P256;
	u8_t pub_key[OPTRUST_NIST_P256_PUB_KEY_LEN] = { 0 };
	size_t pub_key_len = OPTRUST_NIST_P256_PUB_KEY_LEN;

	s64_t start_time = k_uptime_get();

	/* Generate an ECC keypair and export the public key */
	int res = optrust_ecc_gen_keys_oid(&ctx, sec_key_oid, key_alg, key_usage, pub_key, &pub_key_len);

	LOG_INF("optrust_ecc_gen_keys_oid res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_HEXDUMP_INF(pub_key, OPTRUST_NIST_P256_PUB_KEY_LEN, "Public key:");

	u8_t signature[OPTRUST_NIST_P256_SIGNATURE_LEN] = { 0 };
	size_t signature_len = OPTRUST_NIST_P256_SIGNATURE_LEN;

	start_time = k_uptime_get();

	/* Use the secret key to create a signature */
	res = optrust_ecdsa_sign_oid(&ctx, sec_key_oid, test_digest, OPTRUST_SHA256_DIGEST_LEN,
				     signature, &signature_len);

	LOG_INF("optrust_ecdsa_sign_oid res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_HEXDUMP_INF(signature, OPTRUST_NIST_P256_SIGNATURE_LEN, "Signature:");

	start_time = k_uptime_get();
	/* Verify the generated signature */
	res = optrust_ecdsa_verify_ext(&ctx, key_alg, pub_key, pub_key_len,
				       test_digest, OPTRUST_SHA256_DIGEST_LEN,
				       signature, signature_len);
	LOG_INF("optrust_ecdsa_verify_ext res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_INF("ECDSA Verify: %s", res == 0 ? "PASS" : "FAIL");
}


/*
 * In this example, the complete flow of an ECC signature operation when the key is
 * used only temporarlily is described.
 * It starts with generating a key pair on the OPTIGA Trust M in a session context,
 * continues with the signature operation and finishes with the signature verification.
 */
static void example_session_ctx()
{
	/* Acquire a session to temporarily store the key */
	u16_t sec_key_oid = 0;
	int res = optrust_session_acquire(&ctx, &sec_key_oid);

	if (res != 0) {
		LOG_ERR("Failed to request session context");
		return;
	}

	const enum OPTRUST_KEY_USAGE_FLAG key_usage = OPTRUST_KEY_USAGE_FLAG_SIGN;
	const enum OPTRUST_ALGORITHM key_alg = OPTRUST_ALGORITHM_NIST_P256;
	u8_t pub_key[OPTRUST_NIST_P256_PUB_KEY_LEN] = { 0 };
	size_t pub_key_len = OPTRUST_NIST_P256_PUB_KEY_LEN;

	s64_t start_time = k_uptime_get();

	/* Generate an ECC private key in the session context and export the public key */
	res = optrust_ecc_gen_keys_oid(&ctx, sec_key_oid, key_alg, key_usage,
				       pub_key, &pub_key_len);

	LOG_INF("optrust_ecc_gen_keys_oid res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_HEXDUMP_INF(pub_key, OPTRUST_NIST_P256_PUB_KEY_LEN, "Public key:");

	u8_t signature[OPTRUST_NIST_P256_SIGNATURE_LEN] = { 0 };
	size_t signature_len = OPTRUST_NIST_P256_SIGNATURE_LEN;

	start_time = k_uptime_get();

	/* Use the secret key in the session context to create a signature */
	res = optrust_ecdsa_sign_oid(&ctx, sec_key_oid, test_digest, OPTRUST_SHA256_DIGEST_LEN,
				     signature, &signature_len);

	LOG_INF("optrust_ecdsa_sign_oid res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_HEXDUMP_INF(signature, OPTRUST_NIST_P256_SIGNATURE_LEN, "Signature:");

	start_time = k_uptime_get();
	/* Verify the generated signature */
	res = optrust_ecdsa_verify_ext(&ctx, key_alg, pub_key, pub_key_len,
				       test_digest, OPTRUST_SHA256_DIGEST_LEN,
				       signature, signature_len);
	LOG_INF("optrust_ecdsa_verify_ext res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_INF("ECDSA Verify: %s", res == 0 ? "PASS" : "FAIL");

	/* Return the session context to the pool */
	optrust_session_release(&ctx, sec_key_oid);
}

static void example_power()
{
	u8_t dummy[1] = { 0 };
	size_t dummy_len = 1;

	/* Read some data to make sure OPTIGA Trust M is awake */
	optrust_data_get(&ctx, OPTRUST_OID_COPROCESSOR_UID, 0, dummy, &dummy_len);
	LOG_INF("The OPTIGA Trust M will turn off in a few seconds to save power (Power LED off)");

	k_msleep(10000);

	LOG_INF("The OPTIGA Trust M will automatically turn on, to execute the next command (Power LED on)");
	optrust_data_get(&ctx, OPTRUST_OID_COPROCESSOR_UID, 0, dummy, &dummy_len);
}

void main(void)
{
	LOG_INF("Hello OPTIGA");
	dev = device_get_binding("trust-m");

	if (dev == NULL) {
		LOG_INF("Could not get Trust M device\n");
		return;
	}

	LOG_INF("Found Trust M device");

	s64_t start_time = k_uptime_get();

	/* Initialize the command library */
	int res = optrust_init(&ctx, dev, apdu_buf, OPTRUST_CERT_READ_APDU_SIZE);

	LOG_INF("ifx_optiga_trust_init res: %d, took %dms", res, (int) k_uptime_delta(&start_time));

	u8_t coprocessor_uid[OPTRUST_COPROCESSOR_UID_LEN] = { 0 };
	size_t coprocessor_uid_len = OPTRUST_COPROCESSOR_UID_LEN;

	start_time = k_uptime_get();

	/* Read the Co-Processor UID as a basic test of the Trust M working */
	res = optrust_data_get(&ctx, OPTRUST_OID_COPROCESSOR_UID, 0, coprocessor_uid, &coprocessor_uid_len);

	LOG_INF("optrust_data_get res: %d, took %dms", res, (int) k_uptime_delta(&start_time));
	LOG_HEXDUMP_INF(coprocessor_uid, coprocessor_uid_len, "Co-processor UID:");

	/* Activate Shielded Connection */
	start_shielded_connection();

	/* More detailed examples */
	example_ecc();
	example_rsa();
	example_session_ctx();
	example_power();

	LOG_INF("Examples finished");
}
