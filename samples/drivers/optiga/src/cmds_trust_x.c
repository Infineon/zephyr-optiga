/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/crypto/optiga.h>
#include <sys/byteorder.h>

#include "cmds_trust_x.h"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(cmds_x);

#define OPTIGA_TRUSTX_CMD_GET_DATA_OBJECT 0x81
#define OPTIGA_TRUSTX_CMD_SET_DATA_OBJECT 0x82


int cmds_trust_x_init(struct cmds_ctx *ctx, struct device *dev, u8_t *apdu_buf, size_t apdu_buf_len)
{
	ctx->dev = dev;
	ctx->apdu_buf = apdu_buf;
	ctx->apdu_buf_len = apdu_buf_len;

	return 0;
}

void cmds_trust_x_free(struct cmds_ctx *ctx)
{
}

int cmds_trust_x_get_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len)
{
	/* use the first part of the APDU buffer as tx, second as rx buffer */
	u8_t *tx_buf = ctx->apdu_buf;

	/* Command Code */
	*tx_buf = OPTIGA_TRUSTX_CMD_GET_DATA_OBJECT;
	tx_buf++;

	/* Read Data */
	*tx_buf = 0x00;
	tx_buf++;

	/* Length of the Command */
	sys_put_be16(0x06, tx_buf);
	tx_buf += 2;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Length */
	sys_put_be16(*len, tx_buf);
	tx_buf += 2;

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	optiga_enqueue_apdu(ctx->dev, &ctx->apdu);

	struct k_poll_event events[1] = {
        K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL,
                                 K_POLL_MODE_NOTIFY_ONLY,
                                 &ctx->apdu.finished),
	};

	k_poll(events, 1, K_FOREVER);
	int result_code = events[0].signal->result;

	if(result_code != OPTIGA_STATUS_CODE_SUCCESS) {
		LOG_INF("GetDataObject Error Code: %d", result_code);
		return -EIO;
	}

	/* Parse response */

	/* need at least the 4 bytes of response data */
	__ASSERT(ctx->apdu.rx_len >= 4, "Malformed APDU");

	u8_t *rx_buf = ctx->apdu.rx_buf;

	/* Failed APDUs should never reach this layer */
	__ASSERT(*rx_buf == 0x00, "Unexpected failed APDU");
	rx_buf++;

	/* Undefined byte */
	rx_buf++;

	u16_t rx_len = sys_get_be16(rx_buf);

	if(rx_len > *len) {
		return -ENOMEM;
	}

	rx_buf += 2;

	// TODO(chr): out of bounds read check

	memcpy(buf, rx_buf, rx_len);
	*len = rx_len;
	return 0;
}

int cmds_trust_x_set_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, const u8_t *buf, size_t len)
{
	/* use the first part of the APDU buffer as tx, second as rx buffer */
	u8_t *tx_buf = ctx->apdu_buf;

	/* Command Code */
	*tx_buf = OPTIGA_TRUSTX_CMD_SET_DATA_OBJECT;
	tx_buf++;

	/* Erase and Write Data */
	*tx_buf = 0x40;
	tx_buf++;

	/* Length of the Tx APDU */
	// TODO(chr): prevent overflow
	u16_t apdu_len = len + 4;
	sys_put_be16(apdu_len, tx_buf);
	tx_buf += 2;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Data */
	memcpy(tx_buf, buf, len);
	tx_buf += len;

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	optiga_enqueue_apdu(ctx->dev, &ctx->apdu);

	struct k_poll_event events[1] = {
        K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL,
                                 K_POLL_MODE_NOTIFY_ONLY,
                                 &ctx->apdu.finished),
	};

	k_poll(events, 1, K_FOREVER);

	int result_code = events[0].signal->result;

	if(result_code != OPTIGA_STATUS_CODE_SUCCESS) {
		LOG_INF("SetDataObject Error Code: %d", result_code);
		return -EIO;
	}

	return 0;
}
