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

#endif /* CMDS_TRUST_X_H_ */