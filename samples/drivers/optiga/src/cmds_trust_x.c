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

/* Transmitted APDU fields */
#define OPTIGA_TRUSTX_CMD_OFFSET 0
#define OPTIGA_TRUSTX_PARAM_OFFSET 1
#define OPTIGA_TRUSTX_IN_LEN_OFFSET 2
#define OPTIGA_TRUSTX_IN_DATA_OFFSET 4

/* Response APDU fields */
#define OPTIGA_TRUSTX_STA_OFFSET 0
#define OPTIGA_TRUSTX_OUT_LEN_OFFSET 2
#define OPTIGA_TRUSTX_OUT_DATA_OFFSET 2

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

static void cmds_set_apdu_header(u8_t *buf, u8_t cmd, u8_t param, u16_t in_len)
{
	buf[OPTIGA_TRUSTX_CMD_OFFSET] = cmd;
	buf[OPTIGA_TRUSTX_PARAM_OFFSET] = param;
	sys_put_be16(in_len, &buf[OPTIGA_TRUSTX_IN_LEN_OFFSET]);
}

static void cmds_get_apdu_header(u8_t *buf, u8_t *sta, u16_t *out_len)
{
	if (sta) {
		*sta = buf[OPTIGA_TRUSTX_STA_OFFSET];
	}

	if (out_len) {
		*out_len = sys_get_be16(&buf[OPTIGA_TRUSTX_OUT_LEN_OFFSET]);
	}
}

#define OPTIGA_GET_DATA_CMD_LEN 10
int cmds_trust_x_get_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len)
{
	u8_t *tx_buf = ctx->apdu_buf;
	__ASSERT(ctx->apdu_buf_len >= OPTIGA_GET_DATA_CMD_LEN, "APDU buffer too small");

	cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTX_CMD_GET_DATA_OBJECT,
				0x00, /* Read data */
				0x06 /* Command len, see datasheet Table 8 */);

	tx_buf += OPTIGA_TRUSTX_IN_DATA_OFFSET;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Length */
	sys_put_be16(*len, tx_buf);
	tx_buf += 2;

	/*
	 * Setup APDU for cmd queue, reuse the tx_buf for receiving,
	 * we don't need the written data
	 */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = ctx->apdu_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len;

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

	u8_t sta = 0;
	u16_t out_len = 0;
	cmds_get_apdu_header(rx_buf, &sta, &out_len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	if(out_len > *len) {
		return -ENOMEM;
	}

	// TODO(chr): out of bounds read check
	memcpy(buf, &rx_buf[OPTIGA_TRUSTX_OUT_DATA_OFFSET], out_len);
	*len = out_len;
	return 0;
}

int cmds_trust_x_set_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, const u8_t *buf, size_t len)
{
	/* use the first part of the APDU buffer as tx, second as rx buffer */
	u8_t *tx_buf = ctx->apdu_buf;

	__ASSERT(ctx->apdu_buf_len >= (len + 8), "APDU buffer too small");

	cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTX_CMD_SET_DATA_OBJECT,
				0x40, /* Erase and Write Data */
				len + 4 /* Length of the Tx APDU */
					// TODO(chr): prevent overflow
			);

	tx_buf += OPTIGA_TRUSTX_IN_DATA_OFFSET;

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
