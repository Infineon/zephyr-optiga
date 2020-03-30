/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRE_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRE_H_

#include <device.h>

#include <mbedtls/ccm.h>

#define OPTIGA_PRE_PRE_SHARED_SECRET_LEN 64
#define OPTIGA_PRE_AES128_KEY_LEN 16
#define OPTIGA_PRE_AES128_NONCE_LEN 8

#define OPTIGA_PRE_MAC_LEN 8
#define OPTIGA_PRE_ASSOC_DATA_LEN 8

#define OPTIGA_PRE_SCTR_LEN 1
#define OPTIGA_PRE_SSEQ_LEN 4


// TODO(chr): need to define appropriately or make configurable
#define OPTIGA_PRE_MAX_APDU_SIZE 1400

#define OPTIGA_PRE_MAX_ENC_APDU_LEN (OPTIGA_PRE_SCTR_LEN + OPTIGA_PRE_SSEQ_LEN + OPTIGA_PRE_MAC_LEN + OPTIGA_PRE_MAX_APDU_SIZE)

struct present_layer {
	// TODO(chr): need to store permanently? What on re-schedule?
	u8_t pre_shared_secret[OPTIGA_PRE_PRE_SHARED_SECRET_LEN];

	u8_t master_enc_key[OPTIGA_PRE_AES128_KEY_LEN];
	u8_t master_dec_key[OPTIGA_PRE_AES128_KEY_LEN];
	u8_t master_enc_nonce[OPTIGA_PRE_AES128_NONCE_LEN];
	u8_t master_dec_nonce[OPTIGA_PRE_AES128_NONCE_LEN];

	u8_t encrypted_apdu[OPTIGA_PRE_MAX_ENC_APDU_LEN];
	size_t encrypted_apdu_len;
	u8_t assoc_data_buf[OPTIGA_PRE_ASSOC_DATA_LEN];

	/* Context used for encrypt/decrypt of packets */
	mbedtls_ccm_context aes_ccm_ctx;
};
int optiga_pre_init(struct device *dev);
int optiga_pre_send_apdu(struct device *dev, const u8_t *data, size_t len);
int optiga_pre_recv_apdu(struct device *dev, u8_t *data, size_t *len);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRE_H_ */