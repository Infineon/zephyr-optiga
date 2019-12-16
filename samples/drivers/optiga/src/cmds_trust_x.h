/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CMDS_TRUST_X_H_
#define CMDS_TRUST_X_H_

#include <device.h>
#include <zephyr.h>
#include <zephyr/types.h>

#include <drivers/crypto/optiga.h>

// TODO(chr): find the maximum APDU size value
#define CMDS_MAX_APDU_SIZE 1600

struct cmds_ctx {
	struct device *dev;
	u8_t *apdu_buf;
	size_t apdu_buf_len;
	struct optiga_apdu apdu;
};

int cmds_trust_x_init(struct cmds_ctx *ctx, struct device *dev, u8_t *apdu_buf, size_t apdu_buf_len);
void cmds_trust_x_free(struct cmds_ctx *ctx);

int cmds_trust_x_get_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len);
int cmds_trust_x_set_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, const u8_t *buf, size_t len);

#define CMDS_TRUSTX_NIST_P256_SIGNATURE_LEN 64
#define CMDS_TRUSTX_NIST_P384_SIGNATURE_LEN 96

#define CMDS_TRUSTX_NIST_P256_PUB_KEY_LEN 64
#define CMDS_TRUSTX_NIST_P384_PUB_KEY_LEN 96

enum CMDS_TRUSTX_ALGORITHM {
	CMDS_TRUSTX_ALGORITHM_NIST_P256 = 0x03,
	CMDS_TRUSTX_ALGORITHM_NIST_P384 = 0x04,
	CMDS_TRUSTX_ALGORITHM_SHA256	= 0xE2
};

int cmds_trust_x_gen_key_ecdsa(struct cmds_ctx *ctx, u16_t oid, enum CMDS_TRUSTX_ALGORITHM alg, u8_t *pub_key, size_t *pub_key_len);
int cmds_trust_x_sign_ecdsa(struct cmds_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len);
int cmds_trust_x_verify_ecdsa_oid(struct cmds_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len);

#endif /* CMDS_TRUST_X_H_ */