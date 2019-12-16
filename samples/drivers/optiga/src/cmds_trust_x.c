/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/crypto/optiga.h>
#include <sys/byteorder.h>

#include "cmds_trust_x.h"
#include "ecdsa_utils.h"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(cmds_x);

#define OPTIGA_TRUSTX_CMD_GET_DATA_OBJECT	0x81
#define OPTIGA_TRUSTX_CMD_SET_DATA_OBJECT	0x82
#define OPTIGA_TRUSTX_CMD_CALC_SIGN		0xB1
#define OPTIGA_TRUSTX_CMD_VERIFY_SIGN		0xB2
#define OPTIGA_TRUSTX_CMD_GEN_KEYPAIR		0xB8

/* Transmitted APDU fields */
#define OPTIGA_TRUSTX_CMD_OFFSET 0
#define OPTIGA_TRUSTX_PARAM_OFFSET 1
#define OPTIGA_TRUSTX_IN_LEN_OFFSET 2
#define OPTIGA_TRUSTX_IN_DATA_OFFSET 4

/* Response APDU fields */
#define OPTIGA_TRUSTX_STA_OFFSET 0
#define OPTIGA_TRUSTX_OUT_LEN_OFFSET 2
#define OPTIGA_TRUSTX_OUT_DATA_OFFSET 4

static void set_tlv(u8_t *buf, u8_t tag, u16_t length, u8_t *val, size_t val_len)
{
	buf[0] = tag;
	sys_put_be16(length, &buf[1]);
	memcpy(&buf[3], val, val_len);
}

#define SET_TLV_U8_LEN 4
static void set_tlv_u8(u8_t *buf, u8_t tag, u16_t length, u8_t val)
{
	buf[0] = tag;
	sys_put_be16(length, &buf[1]);
	buf[3] = val;
}

#define SET_TLV_U16_LEN 5
static void set_tlv_u16(u8_t *buf, u8_t tag, u16_t length, u16_t val)
{
	buf[0] = tag;
	sys_put_be16(length, &buf[1]);
	sys_put_be16(val, &buf[3]);
}

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

int cmds_trust_x_sign_ecdsa(struct cmds_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len)
{
	u8_t *tx_buf = ctx->apdu_buf;

	__ASSERT(ctx->apdu_buf_len >= (digest_len + 12), "APDU buffer too small");

	cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTX_CMD_CALC_SIGN,
				0x11, /* ECDSA FIPS 186-3 w/o hash */
				digest_len + 8 /* Length of the Tx APDU */
					// TODO(chr): prevent overflow
			);

	tx_buf += OPTIGA_TRUSTX_IN_DATA_OFFSET;

	/* First parameter */
	*tx_buf = 0x01;
	tx_buf++;

	/* Digest length */
	sys_put_be16(digest_len, tx_buf);
	tx_buf += 2;

	/* Digest */
	memcpy(tx_buf, digest, digest_len);
	tx_buf += digest_len;

	/* Second parameter */
	*tx_buf = 0x03;
	tx_buf++;

	/* OID length */
	sys_put_be16(2, tx_buf);
	tx_buf += 2;

	/* OID */
	sys_put_be16(oid, tx_buf);
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
		LOG_INF("SetDataObject Error Code: %d", result_code);
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


	/* decode to raw RS values */
	bool success = asn1_to_ecdsa_rs(&rx_buf[OPTIGA_TRUSTX_OUT_DATA_OFFSET], out_len, signature, signature_len);
	if(!success) {
		LOG_ERR("Failed to decode signature");
		// TODO(chr): find proper return value
		return -1;
	}

	return 0;
}

int cmds_trust_x_verify_ecdsa_oid(struct cmds_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len)
{
	u8_t *tx_buf = ctx->apdu_buf;

	__ASSERT(ctx->apdu_buf_len >= (digest_len + 15), "APDU buffer too small");

	tx_buf += OPTIGA_TRUSTX_IN_DATA_OFFSET;

	/* First parameter */
	*tx_buf = 0x01;
	tx_buf++;

	/* Digest length */
	sys_put_be16(digest_len, tx_buf);
	tx_buf += 2;

	/* Digest */
	memcpy(tx_buf, digest, digest_len);
	tx_buf += digest_len;

	/* Second parameter */
	*tx_buf = 0x02;
	tx_buf++;

	/* we don't know the lenght of the signature data yet, remember the position */
	u8_t * const sig_len_field = tx_buf;
	tx_buf += 2;

	/* Signature */
	__ASSERT((signature_len % 2) == 0, "Signature must have even number of bytes");
	size_t asn1_sig_len = ctx->apdu_buf_len - (ctx->apdu_buf - tx_buf);
	bool success = ecdsa_rs_to_asn1_integers(signature, signature + signature_len/2, signature_len/2, tx_buf, &asn1_sig_len);
	if(!success) {
		LOG_ERR("Couldn't encode signature");
		return -EINVAL;
	}
	tx_buf += asn1_sig_len;

	/* length of signature is known now */
	sys_put_be16(asn1_sig_len, sig_len_field);

	/* length of whole apdu is also known now */
	cmds_set_apdu_header(ctx->apdu_buf,
				OPTIGA_TRUSTX_CMD_VERIFY_SIGN,
				0x11, /* ECDSA FIPS 186-3 w/o hash */
				digest_len + 11 + asn1_sig_len /* Length of the Tx APDU */
					// TODO(chr): prevent overflow
			);

	/* Third parameter */
	*tx_buf = 0x04;
	tx_buf++;

	/* OID length */
	sys_put_be16(2, tx_buf);
	tx_buf += 2;

	/* OID */
	sys_put_be16(oid, tx_buf);
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
		LOG_INF("SetDataObject Error Code: %d", result_code);
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
	__ASSERT(out_len == 0, "Unexpected data returned");

	return 0;
}

int cmds_trust_x_gen_key_ecdsa(struct cmds_ctx *ctx, u16_t oid, enum CMDS_TRUSTX_ALGORITHM alg,  u8_t *pub_key, size_t *pub_key_len)
{
	u8_t *tx_buf = ctx->apdu_buf;
	__ASSERT(ctx->apdu_buf_len >= 11, "APDU buffer too small");
	__ASSERT(pub_key_len != NULL, "Invalid NULL pointer");


	switch(alg) {
		case CMDS_TRUSTX_ALGORITHM_NIST_P256:
			if(*pub_key_len < CMDS_TRUSTX_NIST_P256_PUB_KEY_LEN) {
				return -EINVAL;
			}
			break;
		case CMDS_TRUSTX_ALGORITHM_NIST_P384:
			if(*pub_key_len < CMDS_TRUSTX_NIST_P384_PUB_KEY_LEN) {
				return -EINVAL;
			}
			break;
		default:
			return -EINVAL;
	}


	cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTX_CMD_GEN_KEYPAIR,
				alg, /* Key algorithm */
				0x09 /* Command len, see datasheet Table 19 */);

	tx_buf += OPTIGA_TRUSTX_IN_DATA_OFFSET;

	/* OID */
	set_tlv_u16(tx_buf, 0x01, 2, oid);
	tx_buf += SET_TLV_U16_LEN;

	/* Key usage identifier */
	set_tlv_u8(tx_buf, 0x02, 1, 0x10); // TODO: export parameter for key usage flags
	tx_buf += SET_TLV_U8_LEN;

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

	rx_buf += OPTIGA_TRUSTX_OUT_DATA_OFFSET;
	__ASSERT(rx_buf[0] == 0x02, "Received Key not a pub key");

	// TODO(chr): decide if we can skip ASN.1 decoding
	/* the following decoding routine only works if the public key has a fixed length */
	__ASSERT(out_len == (*pub_key_len + 7), "Assumption about pub key encoding was wrong");
	rx_buf += 3; // skip tag and length
	rx_buf += 4; // skip ASN.1 tag, length and 2 value bytes
	memcpy(pub_key, rx_buf, *pub_key_len);

	return 0;
}
