/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRE_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRE_H_

#include <device.h>

#include <mbedtls/ccm.h>

#define OPTIGA_PRE_PRE_SHARED_SECRET_LEN 32
#define OPTIGA_PRE_AES128_KEY_LEN 16
#define OPTIGA_PRE_AES128_NONCE_LEN 8

#define OPTIGA_PRE_MAC_LEN 8
// TODO(chr): need to define appropriately or make configurable
#define OPTIGA_PRE_MAX_APDU_SIZE 400

struct present_layer {
	// TODO(chr): need to store permanently? What on re-schedule?
	u8_t pre_shared_secret[OPTIGA_PRE_PRE_SHARED_SECRET_LEN];

	u8_t master_enc_key[OPTIGA_PRE_AES128_KEY_LEN];
	u8_t master_dec_key[OPTIGA_PRE_AES128_KEY_LEN];
	u8_t master_enc_nonce[OPTIGA_PRE_AES128_NONCE_LEN];
	u8_t master_dec_nonce[OPTIGA_PRE_AES128_NONCE_LEN];
	u8_t encrypted_apdu[OPTIGA_PRE_MAC_LEN + OPTIGA_PRE_MAX_APDU_SIZE];

	/* Context used for encrypt/decrypt of packets */
	mbedtls_ccm_context aes_ccm_ctx;

	bool enabled;
};

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRE_H_ */