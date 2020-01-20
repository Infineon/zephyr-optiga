/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include "ifx_optiga_trust_x.h"

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);
struct device *dev = NULL;

/* APDU buffer for the command library */
static u8_t apdu_buf[IFX_OPTIGA_TRUST_MAX_APDU_SIZE] = {0};

/* Buffer for the device certificate of the OPTIGA */
#define CERT_BUFFER_LEN 1024
static u8_t cert_buf[CERT_BUFFER_LEN] = {0};
size_t cert_len = CERT_BUFFER_LEN;

#define DIGEST_LEN 32

// set to '1' to run additional tests
#define RUN_TESTS 0

void main(void)
{
	LOG_INF("Hello OPTIGA");
	dev = device_get_binding("trust-x");

	if (dev == NULL) {
		LOG_INF("Could not get Trust X device\n");
		return;
	}

	LOG_INF("Found Trust X device");

#if RUN_TESTS == 1
	run_tests();
#endif

	struct ifx_optiga_trust_ctx ctx;

	/* Initialize the command library */
	int res = ifx_optiga_trust_init(&ctx, dev, apdu_buf, IFX_OPTIGA_TRUST_MAX_APDU_SIZE);

	LOG_INF("ifx_optiga_trust_init res: %d", res);

	/* read device certificate */
	cert_len = CERT_BUFFER_LEN;
	res = ifx_optiga_trust_get_data_object(&ctx, 0xE0E0, 0, cert_buf, &cert_len);

	LOG_INF("ifx_optiga_trust_get_data_object res: %d", res);
	LOG_HEXDUMP_INF(cert_buf, cert_len, "Full Certificate:");


	k_sleep(100);

	/* Write the stripped device certificate to another data object */
	res = ifx_optiga_trust_set_data_object(&ctx, 0xE0E1, true, 0, cert_buf + 9, cert_len - 9);
	LOG_INF("ifx_optiga_trust_set_data_object res: %d", res);
	k_sleep(100);

	/* Read the stripped device certificate */
	cert_len = CERT_BUFFER_LEN;
	res = ifx_optiga_trust_get_data_object(&ctx, 0xE0E1, 0, cert_buf, &cert_len);

	LOG_INF("ifx_optiga_trust_get_data_object res: %d", res);
	LOG_HEXDUMP_INF(cert_buf, cert_len, "Stripped Certificate:");

	u8_t digest[DIGEST_LEN] = {0};
	u8_t signature[IFX_OPTIGA_TRUST_NIST_P256_SIGNATURE_LEN] = {0};

	s64_t time_stamp = k_uptime_get();

	/* Use the device key to create a signature */
	res = ifx_optiga_trust_sign_ecdsa(&ctx, 0xE0F0, digest, DIGEST_LEN,
		signature, IFX_OPTIGA_TRUST_NIST_P256_SIGNATURE_LEN);

	s32_t milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_trust_sign_ecdsa res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(signature, IFX_OPTIGA_TRUST_NIST_P256_SIGNATURE_LEN, "Signature:");

	k_sleep(100);

	time_stamp = k_uptime_get();

	/* Verify the signature using the stripped certificate */
	res = ifx_optiga_trust_verify_ecdsa_oid(&ctx, 0xE0E1, digest, DIGEST_LEN,
		signature, IFX_OPTIGA_TRUST_NIST_P256_SIGNATURE_LEN);

	milliseconds_spent = k_uptime_delta(&time_stamp);

	LOG_INF("ifx_optiga_trust_verify_ecdsa_oid res: %d, took %d ms", res, milliseconds_spent);
	LOG_INF("VERIFY: %s", res == 0 ? "PASS" : "FAIL");

	u8_t pub_key[IFX_OPTIGA_TRUST_NIST_P256_PUB_KEY_LEN] = {0};
	size_t pub_key_len = IFX_OPTIGA_TRUST_NIST_P256_PUB_KEY_LEN;

	time_stamp = k_uptime_get();

	/* Generate an ECDSA keypair and export the public key */
	res = ifx_optiga_trust_gen_key_ecdsa(&ctx, 0xE100, IFX_OPTIGA_TRUST_ALGORITHM_NIST_P256,
		IFX_OPTIGA_TRUST_KEY_USAGE_FLAG_SIGN, pub_key, &pub_key_len);

	milliseconds_spent = k_uptime_delta(&time_stamp);
	LOG_INF("ifx_optiga_trust_gen_key_ecdsa res: %d, took %d ms", res, milliseconds_spent);
	LOG_HEXDUMP_INF(pub_key, IFX_OPTIGA_TRUST_NIST_P256_PUB_KEY_LEN, "Public key:");

	while(true) {
		k_sleep(1000);
	}
}
