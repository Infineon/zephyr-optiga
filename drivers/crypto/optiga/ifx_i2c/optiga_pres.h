/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRES_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRES_H_

#include <device.h>

#include <mbedtls/ccm.h>

#define OPTIGA_PRES_PRE_SHARED_SECRET_LEN 64
#define OPTIGA_PRES_AES128_KEY_LEN 16
#define OPTIGA_PRES_AES128_NONCE_LEN 8

#define OPTIGA_PRES_MAC_LEN 8
#define OPTIGA_PRES_ASSOC_DATA_LEN 8
#define OPTIGA_PRES_SCTR_LEN 1
#define OPTIGA_PRES_SEQ_LEN 4
#define OPTIGA_PRES_RND_LEN 32

#define OPTIGA_PRES_LABEL_STRLEN 16
#define OPTIGA_PRES_SHA256_LEN 32
#define OPTIGA_PRES_DERIVED_SECRET_LEN 40

#define OPTIGA_PRES_OVERHEAD (OPTIGA_PRES_SCTR_LEN + OPTIGA_PRES_SEQ_LEN + OPTIGA_PRES_MAC_LEN)

// TODO(chr): need to define appropriately or make configurable
#define OPTIGA_PRES_MAX_APDU_SIZE 1400

#define OPTIGA_PRES_MAX_ENC_APDU_LEN (OPTIGA_PRES_OVERHEAD + OPTIGA_PRES_MAX_APDU_SIZE)

// TODO(chr): find out the longest message that needs to fit here
#define OPTIGA_PRES_SCRATCH_LEN 60

struct optiga_pres_handshake_buf {
	// TODO(chr): better naming
	uint8_t scratch[OPTIGA_PRES_SCRATCH_LEN];
	size_t scratch_len;
	// TODO(chr): better naming
	uint8_t scratch2[OPTIGA_PRES_SCRATCH_LEN];
	uint8_t rnd[OPTIGA_PRES_RND_LEN];
	uint8_t deriv_secret[OPTIGA_PRES_DERIVED_SECRET_LEN];

	/* Scratch buffers for tls_prf_sha256 */
	uint8_t tmp[OPTIGA_PRES_LABEL_STRLEN + OPTIGA_PRES_SHA256_LEN + OPTIGA_PRES_RND_LEN];
	uint8_t h_i[OPTIGA_PRES_SHA256_LEN];
};

/* Buffer for encrypting and decrypting data after the Handshake */
struct optiga_pres_operation_buf {
	uint8_t encrypted_apdu[OPTIGA_PRES_MAX_ENC_APDU_LEN];
	size_t encrypted_apdu_len;
};

struct present_layer {
	uint8_t pre_shared_secret[OPTIGA_PRES_PRE_SHARED_SECRET_LEN];

	uint8_t master_enc_key[OPTIGA_PRES_AES128_KEY_LEN];
	uint8_t master_dec_key[OPTIGA_PRES_AES128_KEY_LEN];
	uint8_t master_enc_nonce[OPTIGA_PRES_AES128_NONCE_LEN];
	uint8_t master_dec_nonce[OPTIGA_PRES_AES128_NONCE_LEN];

	uint8_t assoc_data_buf[OPTIGA_PRES_ASSOC_DATA_LEN];

	/* Context used for encryption/decryption of packets */
	mbedtls_ccm_context aes_ccm_ctx;

	union {
		struct optiga_pres_operation_buf op;
		struct optiga_pres_handshake_buf hs;
	} buf;

	/* Protocol version */
	uint8_t pver;
};

int optiga_pres_init(struct device *dev);
int optiga_pres_set_shared_secret(struct device *dev, const uint8_t *ssec, size_t ssec_len);
bool optiga_pres_need_rehandshake(struct device *dev);
int optiga_pres_do_handshake(struct device *dev);
int optiga_pres_save_ctx(struct device *dev);
int optiga_pres_restore_ctx(struct device *dev);
int optiga_pres_send_apdu(struct device *dev, const uint8_t *data, size_t len);
int optiga_pres_recv_apdu(struct device *dev, uint8_t *data, size_t *len);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PRES_H_ */