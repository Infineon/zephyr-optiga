/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/crypto/optiga_apdu.h>
#include <drivers/crypto/optiga_trust_m.h>

#include <sys/byteorder.h>

#include "ecdsa_utils.h"
#include "tlv_utils.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(cmds_m, CONFIG_CRYPTO_LOG_LEVEL);

enum OPTIGA_TRUSTM_CMD {
	OPTIGA_TRUSTM_CMD_GET_DATA_OBJECT       = 0x81,
	OPTIGA_TRUSTM_CMD_SET_DATA_OBJECT       = 0x82,
	OPTIGA_TRUSTM_CMD_SET_PROTECTED         = 0x83,
	OPTIGA_TRUSTM_CMD_GET_RANDOM            = 0x8C,
	OPTIGA_TRUSTM_CMD_ENCRYPT_ASYM          = 0x9E,
	OPTIGA_TRUSTM_CMD_DECRYPT_ASYM          = 0x9F,
	OPTIGA_TRUSTM_CMD_CALC_HASH             = 0xB0,
	OPTIGA_TRUSTM_CMD_CALC_SIGN             = 0xB1,
	OPTIGA_TRUSTM_CMD_VERIFY_SIGN           = 0xB2,
	OPTIGA_TRUSTM_CMD_CALC_SSEC             = 0xB3,
	OPTIGA_TRUSTM_CMD_DERIVE_KEY            = 0xB4,
	OPTIGA_TRUSTM_CMD_GEN_KEYPAIR           = 0xB8,
};

/* Parameters for SetDataObject command, see Table 9 */
enum OPTIGA_TRUSTM_SET_DATA_OBJECT {
	OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_DATA        = 0x00,
	OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_METADATA    = 0x01,
	OPTIGA_TRUSTM_SET_DATA_OBJECT_COUNT             = 0x02,
	OPTIGA_TRUSTM_SET_DATA_OBJECT_ERASE_WRITE_DATA  = 0x40,
};

/* Key Agreement Schemes, see Table 24 */
#define OPTIGA_TRUSTM_KEY_AGREEMENT_ECDH 0x01

/* Table 23 - Asymmetric Cipher Suite Identifier */
#define OPTIGA_TRUSTM_ASYM_CIPHER_RSAES_PKCS1_1_5 0x11

/* Table 26 - Signature Schemes */
#define OPTIGA_TRUSTM_SIGNATURE_SCHME_ECDSA_FIPS_186_3 0x11

/* Transmitted APDU fields */
#define OPTIGA_TRUSTM_CMD_OFFSET 0
#define OPTIGA_TRUSTM_PARAM_OFFSET 1
#define OPTIGA_TRUSTM_IN_LEN_OFFSET 2
#define OPTIGA_TRUSTM_IN_DATA_OFFSET 4

#define OPTIGA_TRUSTM_IN_LEN_MAX U16_MAX

/* Response APDU fields */
#define OPTIGA_TRUSTM_STA_OFFSET 0
#define OPTIGA_TRUSTM_OUT_LEN_OFFSET 2
#define OPTIGA_TRUSTM_OUT_DATA_OFFSET 4

#define DER_TAG_BITSTRING 0x03
#define DER_TAG_OCTET_STRING 0x04
/* Tag + Length + Unused bits field */
#define DER_BITSTRING_OVERHEAD 3
/* DER BITSTRING encoding overhead  + Compressed point marker */
#define DER_BITSTRING_PK_OVERHEAD (DER_BITSTRING_OVERHEAD + 1)
/* Compressed point marker for ECC keys */
#define DER_BITSTRING_COMPRESSED_POINT_MARKER 0x04
/* For encoding length in a single byte */
#define DER_LENGTH_SINGLE_MAX 127
/* Tag + Length + Stuffing byte */
#define DER_INTEGER_OVERHEAD 3

/**
 * @brief Store a raw public key as a compressed point in ASN.1 DER BITSTRING encoding
 * @param buf Output buffer for the encoded data
 * @param buf_len Length of buf
 * @param pub_key Raw public key to encode
 * @param pub_key_len Length of pub_key in bytes
 * @return Number of added bytes, 0 on error
 * @note This function can only encode complete bytes and not single bits.
 *       It can also only encode a maximum of 125 bytes.
 */
static size_t set_pub_key_as_bitstring(uint8_t *buf, size_t buf_len, const uint8_t *pub_key, size_t pub_key_len)
{
	/* Overhead: Unused bits field + Compressed point marker */
	if (pub_key_len > (DER_LENGTH_SINGLE_MAX - 2)) {
		/* Length field overflow */
		return 0;
	}

	if ((pub_key_len + DER_BITSTRING_PK_OVERHEAD) > buf_len) {
		/* Output buffer overflow */
		return 0;
	}

	*buf = DER_TAG_BITSTRING;
	buf++;

	/* Length including "unused bits" value and compressed point marker */
	*buf = pub_key_len + 2;
	buf++;

	/* Unused bits, only 0 supported here */
	*buf = 0;
	buf++;

	/* Compressed point marker */
	*buf = DER_BITSTRING_COMPRESSED_POINT_MARKER;
	buf++;

	/* actual data */
	memcpy(buf, pub_key, pub_key_len);
	return pub_key_len + DER_BITSTRING_PK_OVERHEAD;
}

/**
 * @brief Extracts a public key from ASN.1 DER encoded data
 * @param buf Buffer with the ASN.1 data
 * @param buf_len Length of buf
 * @param pub_key Buffer for the extracted public key
 * @param pub_key_len Expected length of the public key
 * @return 0 on success, error code otherwise
 * @note This
 */
static int get_pub_key_from_bitstring(uint8_t *buf, size_t buf_len, uint8_t *pub_key, size_t pub_key_len)
{
	/* Validate length */
	if (buf_len != (DER_BITSTRING_PK_OVERHEAD + pub_key_len)) {
		/* Not enough data for pub key */
		return -EIO;
	}

	if (DER_LENGTH_SINGLE_MAX < (pub_key_len + 2)) {
		/* Only single byte length encoding is supported */
		return -EIO;
	}

	/* Verify Tag byte */
	if (*buf != DER_TAG_BITSTRING) {
		/* Not an DER BIT STRING */
		return -EIO;
	}

	/* Verify length field */
	buf++;
	if (*buf != (pub_key_len + 2)) {
		/* Length mismatch */
		return -EIO;
	}

	buf++;
	if (*buf != 0) {
		/* "Unused bits\" encoding not supported */
		return -EIO;
	}

	/* Only compressed points are supported here */
	buf++;
	if (*buf != DER_BITSTRING_COMPRESSED_POINT_MARKER) {
		/* Not a compressed point */
		return -EIO;
	}

	buf++;
	memcpy(pub_key, buf, pub_key_len);

	return 0;
}


static size_t cmds_set_apdu_header(uint8_t *apdu_start, enum OPTIGA_TRUSTM_CMD cmd, uint8_t param, uint16_t in_len)
{
	apdu_start[OPTIGA_TRUSTM_CMD_OFFSET] = cmd;
	apdu_start[OPTIGA_TRUSTM_PARAM_OFFSET] = param;
	sys_put_be16(in_len, &apdu_start[OPTIGA_TRUSTM_IN_LEN_OFFSET]);
	return OPTIGA_TRUSTM_IN_DATA_OFFSET;
}

static size_t cmds_get_apdu_header(const uint8_t *apdu_start, uint8_t *sta, uint16_t *out_len)
{
	if (sta) {
		*sta = apdu_start[OPTIGA_TRUSTM_STA_OFFSET];
	}

	if (out_len) {
		*out_len = sys_get_be16(&apdu_start[OPTIGA_TRUSTM_OUT_LEN_OFFSET]);
	}

	return OPTIGA_TRUSTM_IN_DATA_OFFSET;
}

int optrust_init(struct optrust_ctx *ctx, struct device *dev, uint8_t *apdu_buf, size_t apdu_buf_len)
{
	__ASSERT(ctx != NULL && dev != NULL && apdu_buf != NULL, "No NULL parameters allowed");

	ctx->dev = dev;
	ctx->apdu_buf = apdu_buf;
	ctx->apdu_buf_len = apdu_buf_len;

	return 0;
}

void optrust_deinit(struct optrust_ctx *ctx)
{
}

static int cmds_submit_apdu(struct optrust_ctx *ctx, const uint8_t *apdu_end, enum OPTIGA_TRUSTM_CMD cmd, uint8_t param)
{
	const uint8_t *apdu_start = ctx->apdu_buf;

	__ASSERT((apdu_start + OPTIGA_TRUSTM_IN_DATA_OFFSET) <= apdu_end, "Invalid apdu_end pointer");

	const size_t in_data_len = apdu_end - apdu_start - OPTIGA_TRUSTM_IN_DATA_OFFSET;

	if (in_data_len > UINT16_MAX) {
		/* Overflow in inData field */
		return -EINVAL;
	}

	cmds_set_apdu_header(ctx->apdu_buf, cmd, param, (uint16_t) in_data_len);

	/*
	 * Setup APDU for cmd queue, reuse the apdu_buf for receiving,
	 * we don't need the written data
	 */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = apdu_end - apdu_start;
	ctx->apdu.rx_buf = ctx->apdu_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len;

	optiga_enqueue_apdu(ctx->dev, &ctx->apdu);

	struct k_poll_event events[1] = {
		K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL,
					 K_POLL_MODE_NOTIFY_ONLY,
					 &ctx->apdu.finished),
	};

	k_poll(events, 1, K_FOREVER);
	return events[0].signal->result;
}

/**
 * @brief Check the header and length of an APDU in the buffer
 * @param ctx Context too use
 * @param out_len Contains the number of bytes in the outData field of the APDU afterwards
 * @return Pointer to outData field of the APDU on success, NULL otherwise
 */
static uint8_t *cmds_check_apdu(struct optrust_ctx *ctx, uint16_t *out_len)
{
	__ASSERT(ctx != NULL && out_len != NULL, "No NULL parameters allowed");

	/* need at least the 4 bytes of response data */
	if (ctx->apdu.rx_len < OPTIGA_TRUSTM_OUT_DATA_OFFSET) {
		LOG_ERR("Malformed APDU");
		return NULL;
	}

	uint8_t *rx_buf = ctx->apdu.rx_buf;

	uint8_t sta = 0;

	rx_buf += cmds_get_apdu_header(rx_buf, &sta, out_len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	/* Ensure length of APDU and length of buffer match */
	if (*out_len != (ctx->apdu.rx_len - OPTIGA_TRUSTM_OUT_DATA_OFFSET)) {
		LOG_ERR("Incomplete APDU");
		return NULL;
	}

	return rx_buf;
}

/**
 * @brief Check that the APDU in the receive buffer is empty with success status
 * @param ctx Context too use
 * @return 0 on success, error code else
 */
static int cmds_check_apdu_empty(struct optrust_ctx *ctx)
{
	/* Empty APDU is 4 bytes */
	if (ctx->apdu.rx_len != OPTIGA_TRUSTM_OUT_DATA_OFFSET) {
		/* Invalid length */
		return -EIO;
	}

	/* Bytes 0, 2 and 3 are expected to be 0x00 for an empty APDU */
	if (ctx->apdu.rx_buf[0] != 0x00 || ctx->apdu.rx_buf[2] != 0x00
	    || ctx->apdu.rx_buf[3] != 0x00) {
		/* APDU not empty */
		return -EIO;
	}

	return 0;
}

/* Must be synced to OPTIGA_IGNORE_HIBERNATE in crypto_optiga.h */
#define OPTIGA_TRUSTM_WAKE_LOCK_IDX_START 8
#define OPTIGA_TRUSTM_WAKE_LOCK_IDX_END 32

int optrust_wake_lock_acquire(struct optrust_ctx *ctx, int *token)
{
	__ASSERT(ctx != NULL && token != NULL, "No NULL parameters allowed");

	int session = OPTIGA_TRUSTM_WAKE_LOCK_IDX_START;

	for (; session < OPTIGA_TRUSTM_WAKE_LOCK_IDX_END; session++) {
		bool acquired = optiga_session_acquire(ctx->dev, session);
		if (acquired) {
			/* found free slot */
			break;
		}
	}

	if (session == OPTIGA_TRUSTM_WAKE_LOCK_IDX_END) {
		/* No free session contexts */
		return -EBUSY;
	}

	*token = session;
	return 0;
}

void optrust_wake_lock_release(struct optrust_ctx *ctx, int token)
{
	__ASSERT(ctx != NULL, "No NULL parameters allowed");
	__ASSERT(token >= OPTIGA_TRUSTM_WAKE_LOCK_IDX_START
		 && token < OPTIGA_TRUSTM_WAKE_LOCK_IDX_END, "Token invalid");

	optiga_session_release(ctx->dev, token);
}

#define OPTIGA_TRUSTM_SESSIONS 4

/* See Figure 29 - Overview Data and Key Store */
static const uint16_t optiga_trustm_sessions[OPTIGA_TRUSTM_SESSIONS] = {
	0xE100,
	0xE101,
	0xE102,
	0xE103,
};

int optrust_session_acquire(struct optrust_ctx *ctx, uint16_t *oid)
{
	int session = 0;

	for (; session < OPTIGA_TRUSTM_SESSIONS; session++) {
		bool acquired = optiga_session_acquire(ctx->dev, session);
		if (acquired) {
			/* found free slot */
			break;
		}
	}

	if (session == OPTIGA_TRUSTM_SESSIONS) {
		/* No free session contexts */
		return -EBUSY;
	}

	*oid = optiga_trustm_sessions[session];
	return 0;
}

int optrust_session_release(struct optrust_ctx *ctx, uint16_t oid)
{
	int session = 0;

	for (; session < OPTIGA_TRUSTM_SESSIONS; session++) {
		if (oid == optiga_trustm_sessions[session]) {
			optiga_session_release(ctx->dev, session);
			return 0;
		}
	}

	/* Invalid OID */
	return -EINVAL;
}

int optrust_shielded_connection_psk_start(struct optrust_ctx *ctx, const uint8_t *psk, size_t psk_len)
{
	__ASSERT(ctx != NULL && psk != NULL, "No NULL parameters allowed");

	/* Tell driver to enable shielded connection */
	int res = optiga_start_shield(ctx->dev, psk, psk_len);

	if (res != 0) {
		return res;
	}

	/* Submit a dummy APDU to trigger an immediate handshake */
	uint8_t dummy = 0;
	size_t dummy_len = 1;

	/* If that APDU fails, it's because shielded connection was not enabled properly */
	return optrust_data_get(ctx, 0xE0C2, 0, &dummy, &dummy_len);
}

int optrust_data_get(struct optrust_ctx *ctx, uint16_t oid, size_t offs, uint8_t *buf, size_t *len)
{
	__ASSERT(ctx != NULL && buf != NULL && len != NULL, "No NULL parameters allowed");

	if (offs > UINT16_MAX || *len > UINT16_MAX) {
		/* Prevent overflow in parameter encoding */
		return -EINVAL;
	}

	static const size_t cmd_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + 6;

	if (ctx->apdu_buf_len < cmd_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Length */
	sys_put_be16(*len, tx_buf);
	tx_buf += 2;

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_GET_DATA_OBJECT,
					   0x00 /* Read data */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("GetDataObject Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	const uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len > *len) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	memcpy(buf, out_data, out_len);
	*len = out_len;
	return 0;
}

int optrust_metadata_get(struct optrust_ctx *ctx, uint16_t oid, uint8_t *buf, size_t *len)
{
	__ASSERT(ctx != NULL && buf != NULL && len != NULL, "No NULL parameters allowed");

	static const size_t cmd_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + 2;

	if (ctx->apdu_buf_len < cmd_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_GET_DATA_OBJECT,
					   0x01 /* Read metadata */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("GetDataObject Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

static int optrust_int_data_set(struct optrust_ctx *ctx, enum OPTIGA_TRUSTM_SET_DATA_OBJECT param, uint16_t oid, size_t offs, const uint8_t *data, size_t len)
{
	__ASSERT(ctx != NULL && data != NULL, "No NULL parameters allowed");

	if (offs > UINT16_MAX) {
		/* Prevent overflow in parameter encoding */
		return -EINVAL;
	}

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + 4;
	const size_t apdu_len = cmd_overhead + len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Data */
	memcpy(tx_buf, data, len);
	tx_buf += len;

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_SET_DATA_OBJECT,
					   (uint8_t) param /* Param */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("SetDataObject Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

int optrust_data_set(struct optrust_ctx *ctx, uint16_t oid, bool erase, size_t offs, const uint8_t *buf, size_t len)
{
	const uint8_t param = erase ? OPTIGA_TRUSTM_SET_DATA_OBJECT_ERASE_WRITE_DATA
		: OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_DATA;

	return optrust_int_data_set(ctx, param, oid, offs, buf, len);
}

int optrust_metadata_set(struct optrust_ctx *ctx, uint16_t oid, const uint8_t *data, size_t data_len)
{
	return optrust_int_data_set(ctx, OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_METADATA, oid, 0, data, data_len);
}

int optrust_counter_inc(struct optrust_ctx *ctx, uint16_t oid, uint8_t inc)
{
	return optrust_int_data_set(ctx, OPTIGA_TRUSTM_SET_DATA_OBJECT_COUNT, oid, 0, &inc, 1);
}

/* See 4.4.1.5 SetObjectProtected footnotes for the source */
#define OPTIGA_DATA_PROTECTED_UPDATE_BLOCK_LEN 640
int optrust_data_protected_update(struct optrust_ctx *ctx, const uint8_t *manifest, size_t manifest_len,
				  const uint8_t *payload, size_t payload_len)
{
	// TODO(chr): check if this function needs to be atomic or if other APDUs can be mixed in
	__ASSERT(ctx != NULL && manifest != NULL && payload != NULL, "No NULL parameters allowed");

	if (manifest_len > UINT16_MAX) {
		/* Prevent overflow in parameter encoding */
		return -EINVAL;
	}

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD;
	const size_t manifest_apdu_len = cmd_overhead + manifest_len;

	if (manifest_apdu_len > ctx->apdu_buf_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Manifest */
	tx_buf += set_tlv(tx_buf, 0x30, manifest, manifest_len);

	int res_code = cmds_submit_apdu(ctx,
					tx_buf,
					OPTIGA_TRUSTM_CMD_SET_PROTECTED,
					0x01 /* manifest format (CDDL CBOR) */);

	if (optiga_is_driver_error(res_code)) {
		/* Our driver errored */
		return res_code;
	} else if (optiga_is_device_error(res_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("SetObjectProtected Error Code: 0x%02x", res_code);
		return -EIO;
	}

	/* No response data expected */
	res_code =  cmds_check_apdu_empty(ctx);
	if (res_code != 0) {
		return res_code;
	}

	const uint8_t *cur_payload = payload;
	size_t remaining_len = payload_len;

	/* Send 'continue' APDU */
	while (remaining_len > OPTIGA_DATA_PROTECTED_UPDATE_BLOCK_LEN) {
		const size_t continue_apdu_len = cmd_overhead + OPTIGA_DATA_PROTECTED_UPDATE_BLOCK_LEN;
		if (continue_apdu_len > ctx->apdu_buf_len) {
			/* Prevent overflow in APDU buffer */
			return -ENOMEM;
		}

		/* Skip to APDU inData field */
		tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

		/* Continue Payload */
		tx_buf += set_tlv(tx_buf, 0x32, cur_payload, OPTIGA_DATA_PROTECTED_UPDATE_BLOCK_LEN);

		res_code = cmds_submit_apdu(ctx,
					    tx_buf,
					    OPTIGA_TRUSTM_CMD_SET_PROTECTED,
					    0x01 /* manifest format (CDDL CBOR) */);

		if (optiga_is_driver_error(res_code)) {
			/* Our driver errored */
			return res_code;
		} else if (optiga_is_device_error(res_code)) {
			/* OPTIGA produced an error code */
			LOG_INF("SetObjectProtected Error Code: 0x%02x", res_code);
			return -EIO;
		}

		/* No response data expected */
		res_code =  cmds_check_apdu_empty(ctx);
		if (res_code != 0) {
			return res_code;
		}

		cur_payload += OPTIGA_DATA_PROTECTED_UPDATE_BLOCK_LEN;
		remaining_len -= OPTIGA_DATA_PROTECTED_UPDATE_BLOCK_LEN;
	}

	/* Send 'final' APDU */

	const size_t final_apdu_len = cmd_overhead + remaining_len;

	if (final_apdu_len > ctx->apdu_buf_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Final Payload */
	tx_buf += set_tlv(tx_buf, 0x31, cur_payload, remaining_len);

	res_code = cmds_submit_apdu(ctx,
				    tx_buf,
				    OPTIGA_TRUSTM_CMD_SET_PROTECTED,
				    0x01 /* manifest format (CDDL CBOR) */);

	if (optiga_is_driver_error(res_code)) {
		/* Our driver errored */
		return res_code;
	} else if (optiga_is_device_error(res_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("SetObjectProtected Error Code: 0x%02x", res_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

int optrust_ecdsa_sign_oid(struct optrust_ctx *ctx, uint16_t oid, const uint8_t *digest, size_t digest_len, uint8_t *signature, size_t *signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + digest_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	if (digest_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest to be signed */
	tx_buf += set_tlv(tx_buf, 0x01, digest, (uint16_t) digest_len);

	/* OID of signature key */
	tx_buf += set_tlv_u16(tx_buf, 0x03, oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_CALC_SIGN,
					   OPTIGA_TRUSTM_SIGNATURE_SCHME_ECDSA_FIPS_186_3);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcSign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	const uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	size_t expected_sig_len = 0;

	if (out_len < OPTRUST_NIST_P256_SIGNATURE_LEN) {
		/* Unexpected data returned */
		return -EIO;
	} else if (out_len <= (OPTRUST_NIST_P256_SIGNATURE_LEN + 2 * DER_INTEGER_OVERHEAD)) {
		expected_sig_len = OPTRUST_NIST_P256_SIGNATURE_LEN;
	} else if (out_len < OPTRUST_NIST_P384_SIGNATURE_LEN) {
		/* Unexpected data returned */
		return -EIO;
	} else if (out_len <= (OPTRUST_NIST_P384_SIGNATURE_LEN + 2 * DER_INTEGER_OVERHEAD)) {
		expected_sig_len = OPTRUST_NIST_P384_SIGNATURE_LEN;
	} else {
		/* Unexpected data returned */
		return -EIO;
	}

	if (*signature_len < expected_sig_len) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	/* decode to raw RS values */
	bool success = asn1_to_ecdsa_rs(out_data, out_len, signature, expected_sig_len);

	if (!success) {
		LOG_ERR("Failed to decode signature");
		return -EIO;
	}

	return 0;
}

int optrust_ecdsa_verify_ext(struct optrust_ctx *ctx, enum OPTRUST_ALGORITHM alg,
			     const uint8_t *pub_key, size_t pub_key_len,
			     const uint8_t *digest, size_t digest_len,
			     const uint8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");

	switch (alg) {
	case OPTRUST_ALGORITHM_NIST_P256:
		if (pub_key_len != OPTRUST_NIST_P256_PUB_KEY_LEN) {
			return -EINVAL;
		}
		break;
	case OPTRUST_ALGORITHM_NIST_P384:
		if (pub_key_len != OPTRUST_NIST_P384_PUB_KEY_LEN) {
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + TLV_OVERHEAD + SET_TLV_U16_LEN;
	const size_t apdu_block_1_len = cmd_overhead + digest_len;

	if (apdu_block_1_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (digest_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, (uint16_t) digest_len);

	/* Second parameter */
	*tx_buf = 0x02;
	tx_buf++;

	/* we don't know the length of the signature data and public key yet, remember the position */
	uint8_t *const sig_len_field = tx_buf;

	tx_buf += 2;

	/* Signature */

	size_t remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf) - SET_TLV_U16_LEN;
	size_t asn1_sig_len = remaining_apdu_len;

	__ASSERT((signature_len % 2) == 0, "Signature must have even number of bytes");
	bool success = ecdsa_rs_to_asn1_integers(signature, signature + signature_len / 2, signature_len / 2, tx_buf, &asn1_sig_len);

	if (!success) {
		LOG_ERR("Couldn't encode signature");
		return -EINVAL;
	}
	tx_buf += asn1_sig_len;

	if (asn1_sig_len > UINT16_MAX) {
		LOG_ERR("Signature too long");
		return -EINVAL;
	}

	/* length of signature is known now */
	sys_put_be16(asn1_sig_len, sig_len_field);

	const size_t apdu_block_2_len = SET_TLV_U8_LEN + TLV_OVERHEAD;

	remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf);
	if (apdu_block_2_len > remaining_apdu_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	/* Algorithm identifier of public key */
	__ASSERT(alg >= 0 && alg <= UINT8_MAX, "Invalid algorithm identifer");
	tx_buf += set_tlv_u8(tx_buf, 0x05, (uint8_t) alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	uint8_t *pub_key_len_field = tx_buf;

	tx_buf += 2;

	/* Public key Value */
	remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf);
	size_t pub_key_asn1_len = set_pub_key_as_bitstring(tx_buf, remaining_apdu_len, pub_key, pub_key_len);

	if (pub_key_asn1_len == 0) {
		/* Encoding error */
		return -EINVAL;
	}

	tx_buf += pub_key_asn1_len;

	/* Public key length know now */
	sys_put_be16(pub_key_asn1_len, pub_key_len_field);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_VERIFY_SIGN,
					   OPTIGA_TRUSTM_SIGNATURE_SCHME_ECDSA_FIPS_186_3);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("VerifySign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

int optrust_ecdsa_verify_oid(struct optrust_ctx *ctx, uint16_t oid, const uint8_t *digest, size_t digest_len, const uint8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");
	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + TLV_OVERHEAD + SET_TLV_U16_LEN;
	const size_t apdu_block_1_len = cmd_overhead + digest_len;

	if (apdu_block_1_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (digest_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, (uint16_t) digest_len);

	/* Second parameter */
	*tx_buf = 0x02;
	tx_buf++;

	/* we don't know the length of the signature data yet, remember the position */
	uint8_t *const sig_len_field = tx_buf;

	tx_buf += 2;

	/* Signature */
	size_t remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf) - SET_TLV_U16_LEN;
	size_t asn1_sig_len = remaining_apdu_len;

	__ASSERT((signature_len % 2) == 0, "Signature must have even number of bytes");
	bool success = ecdsa_rs_to_asn1_integers(signature, signature + signature_len / 2, signature_len / 2, tx_buf, &asn1_sig_len);

	if (!success) {
		LOG_ERR("Couldn't encode signature");
		return -EINVAL;
	}
	tx_buf += asn1_sig_len;

	if (asn1_sig_len > UINT16_MAX) {
		/* Overflow in signature length field */
		return -EINVAL;
	}

	/* length of signature is known now */
	sys_put_be16(asn1_sig_len, sig_len_field);

	/* OID of Public Key Certificate */
	tx_buf += set_tlv_u16(tx_buf, 0x04, oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_VERIFY_SIGN,
					   OPTIGA_TRUSTM_SIGNATURE_SCHME_ECDSA_FIPS_186_3);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("VerifySign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

int optrust_int_gen_keys_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_ALGORITHM alg,
			     enum OPTRUST_KEY_USAGE_FLAG key_usage, uint8_t **out_data, size_t *out_data_len)
{
	__ASSERT(ctx != NULL && out_data != NULL && out_data_len != NULL, "No NULL parameters allowed");

	switch (alg) {
	case OPTRUST_ALGORITHM_NIST_P256:       /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_NIST_P384:       /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_RSA_1024:        /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_RSA_2048:        /* Intentional fallthrough */
		break;
	default:
		/* Invalid algorithm */
		return -EINVAL;
	}

	static const size_t cmd_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U8_LEN;

	if (ctx->apdu_buf_len < cmd_len) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	tx_buf += set_tlv_u16(tx_buf, 0x01, oid);

	/* Key usage identifier */
	__ASSERT(key_usage >= 0 && key_usage <= UINT8_MAX, "Invalid key usage identifer");
	tx_buf += set_tlv_u8(tx_buf, 0x02, (uint8_t) key_usage);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_GEN_KEYPAIR,
					   alg /* Key algorithm */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("GenKeyPair Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	uint8_t *res_data = cmds_check_apdu(ctx, &out_len);

	if (res_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	*out_data = res_data;
	*out_data_len = out_len;

	return 0;
}

int optrust_ecc_gen_keys_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_ALGORITHM alg,
			     enum OPTRUST_KEY_USAGE_FLAG key_usage, uint8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL, "No NULL parameters allowed");

	switch (alg) {
	case OPTRUST_ALGORITHM_NIST_P256:
		if (*pub_key_len < OPTRUST_NIST_P256_PUB_KEY_LEN) {
			return -EINVAL;
		}
		*pub_key_len = OPTRUST_NIST_P256_PUB_KEY_LEN;
		break;
	case OPTRUST_ALGORITHM_NIST_P384:
		if (*pub_key_len < OPTRUST_NIST_P384_PUB_KEY_LEN) {
			return -EINVAL;
		}
		*pub_key_len = OPTRUST_NIST_P384_PUB_KEY_LEN;
		break;
	default:
		return -EINVAL;
	}

	uint8_t *out_data = NULL;
	size_t out_len = 0;

	int res = optrust_int_gen_keys_oid(ctx, oid, alg, key_usage, &out_data, &out_len);

	if (res != 0) {
		return res;
	}

	uint8_t tag = 0;
	uint16_t len = 0;
	uint8_t *pub_key_buf = NULL;

	/* Parse secret key */
	size_t tlv_res = get_tlv(out_data, out_len, &tag, &len, &pub_key_buf);
	if (tlv_res == 0) {
		/* Failed to parse TLV data structure */
		return -EIO;
	}

	if (tag != 0x02) {
		/* Received Key not a pub key */
		return -EIO;
	}

	return get_pub_key_from_bitstring(pub_key_buf, len, pub_key, *pub_key_len);
}

static int optrust_int_gen_keys_ext(struct optrust_ctx *ctx,
				    enum OPTRUST_ALGORITHM alg,
				    uint8_t **sec_key, size_t *sec_key_len,
				    uint8_t **pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL
		 && sec_key != NULL && sec_key_len != NULL, "No NULL parameters allowed");

	switch (alg) {
	case OPTRUST_ALGORITHM_NIST_P256:       /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_NIST_P384:       /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_RSA_1024:        /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_RSA_2048:
		break;
	default:
		/* Invalid algorithm */
		return -EINVAL;
	}

	static const size_t cmd_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD;

	if (ctx->apdu_buf_len < cmd_len) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Export key pair in plain */
	tx_buf += set_tlv(tx_buf, 0x07, NULL, 0);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_GEN_KEYPAIR,
					   alg /* Key algorithm */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("GenKeyPair Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	uint8_t tag = 0;
	uint16_t len = 0;

	/* Parse secret key */
	size_t res = get_tlv(out_data, out_len, &tag, &len, sec_key);

	if (res == 0) {
		/* Failed to parse TLV data structure */
		return -EIO;
	}

	if (tag != 0x01) {
		/* Unexpected Tag */
		return -EIO;
	}

	*sec_key_len = len;

	out_data += res;
	out_len -= res;

	res = get_tlv(out_data, out_len, &tag, &len, pub_key);
	if (res == 0) {
		/* Failed to parse TLV data structure */
		return -EIO;
	}

	if (tag != 0x02) {
		/* Unexpected Tag */
		return -EIO;
	}
	*pub_key_len = len;

	return 0;
}

int optrust_ecc_gen_keys_ext(struct optrust_ctx *ctx,
			     enum OPTRUST_ALGORITHM alg,
			     uint8_t *sec_key, size_t *sec_key_len,
			     uint8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL
		 && sec_key != NULL && sec_key_len != NULL, "No NULL parameters allowed");

	switch (alg) {
	case OPTRUST_ALGORITHM_NIST_P256:
		if (*pub_key_len < OPTRUST_NIST_P256_PUB_KEY_LEN
		    || *sec_key_len < OPTRUST_NIST_P256_SEC_KEY_LEN) {
			return -EINVAL;
		}

		*sec_key_len = OPTRUST_NIST_P256_SEC_KEY_LEN;
		*pub_key_len = OPTRUST_NIST_P256_PUB_KEY_LEN;
		break;
	case OPTRUST_ALGORITHM_NIST_P384:
		if (*pub_key_len < OPTRUST_NIST_P384_PUB_KEY_LEN
		    || *sec_key_len < OPTRUST_NIST_P384_SEC_KEY_LEN) {
			return -EINVAL;
		}

		*sec_key_len = OPTRUST_NIST_P384_SEC_KEY_LEN;
		*pub_key_len = OPTRUST_NIST_P384_PUB_KEY_LEN;
		break;
	default:
		return -EINVAL;
	}

	uint8_t *sec_key_asn1 = NULL;
	size_t sec_key_asn1_len = 0;

	uint8_t *pub_key_asn1 = NULL;
	size_t pub_key_asn1_len = 0;

	int res = optrust_int_gen_keys_ext(ctx, alg, &sec_key_asn1, &sec_key_asn1_len,
					   &pub_key_asn1, &pub_key_asn1_len);

	if (res != 0) {
		return 0;
	}

	// TODO(chr): more robust ASN.1 decoding

	/* Secret key is encoded as DER OCTET STRING */

	/* ASN.1 encoding overhead are 2 bytes */
	if (sec_key_asn1_len != (*sec_key_len + 2)) {
		/* Unexpected length */
		return -EIO;
	}

	__ASSERT(sec_key_asn1[0] == DER_TAG_OCTET_STRING, "Not an DER OCTECT STRING");
	__ASSERT(sec_key_asn1[1] == *sec_key_len, "Length mismatch");

	sec_key_asn1 += 2;
	memcpy(sec_key, sec_key_asn1, *sec_key_len);

	/* Public key is encoded as DER BIT STRING */

	return get_pub_key_from_bitstring(pub_key_asn1, pub_key_asn1_len, pub_key, *pub_key_len);
}

/* Tags for CalcHash command, see Table 16 */
enum OPTIGA_TRUSTM_CALC_HASH_TAGS {
	OPTIGA_TRUSTM_CALC_HASH_START           = 0x00,
	OPTIGA_TRUSTM_CALC_HASH_START_FINAL     = 0x01,
	OPTIGA_TRUSTM_CALC_HASH_CONTINUE        = 0x02,
	OPTIGA_TRUSTM_CALC_HASH_FINAL           = 0x03,
	OPTIGA_TRUSTM_CALC_HASH_TERMINATE       = 0x04,
	OPTIGA_TRUSTM_CALC_HASH_FINAL_KEEP      = 0x05,
	OPTIGA_TRUSTM_CALC_HASH_OID_START       = 0x10,
	OPTIGA_TRUSTM_CALC_HASH_OID_START_FINAL = 0x11,
	OPTIGA_TRUSTM_CALC_HASH_OID_CONTINUE    = 0x12,
	OPTIGA_TRUSTM_CALC_HASH_OID_FINAL       = 0x13,
	OPTIGA_TRUSTM_CALC_HASH_OID_FINAL_KEEP  = 0x15,
};

int optrust_sha256_ext(struct optrust_ctx *ctx, const uint8_t *data, size_t data_len,
		       uint8_t *digest, size_t *digest_len)
{
	__ASSERT(ctx != NULL && digest != NULL && digest_len != NULL && data != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD;
	const size_t apdu_len = cmd_overhead + data_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	if (*digest_len < OPTRUST_SHA256_DIGEST_LEN) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	if (data_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Write message data */
	tx_buf += set_tlv(tx_buf, OPTIGA_TRUSTM_CALC_HASH_START_FINAL, data, (uint16_t) data_len);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_CALC_HASH,
					   OPTRUST_ALGORITHM_SHA256 /* Param */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcHash Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	__ASSERT(out_len == (OPTRUST_SHA256_DIGEST_LEN + TLV_OVERHEAD), "Unexpected data returned");

	uint8_t tag = 0;
	uint16_t len = 0;
	uint8_t *out_digest = NULL;

	if (get_tlv(out_data, out_len, &tag, &len, &out_digest) == 0) {
		/* Failed to parse result */
		return -EIO;
	}

	if (tag != 0x01 && len != OPTRUST_SHA256_DIGEST_LEN) {
		/* Invalid data */
		return -EIO;
	}

	memcpy(digest, out_digest, OPTRUST_SHA256_DIGEST_LEN);

	return 0;
}

int optrust_sha256_oid(struct optrust_ctx *ctx,
		       uint16_t oid, size_t offs, size_t len,
		       uint8_t *digest, size_t *digest_len)
{
	__ASSERT(ctx != NULL && digest != NULL && digest_len != NULL, "No NULL parameters allowed");

	if (offs > UINT16_MAX || len > UINT16_MAX) {
		/* Overflow in Offset or Length field */
		return -EINVAL;
	}

	static const size_t cmd_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + 9;

	if (ctx->apdu_buf_len < cmd_len) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	if (*digest_len < OPTRUST_SHA256_DIGEST_LEN) {
		/* Output buffer too small */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Tag */
	*tx_buf = OPTIGA_TRUSTM_CALC_HASH_OID_START_FINAL;
	tx_buf += 1;

	/* Length */
	sys_put_be16(0x06, tx_buf);
	tx_buf += 2;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset in OID */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Length of OID */
	sys_put_be16(len, tx_buf);
	tx_buf += 2;

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_CALC_HASH,
					   OPTRUST_ALGORITHM_SHA256 /* Param */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcHash Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	__ASSERT(out_len == (OPTRUST_SHA256_DIGEST_LEN + 3), "Unexpected data returned");

	uint8_t tag = 0;
	uint16_t out_digest_len = 0;
	uint8_t *out_digest = NULL;

	if (get_tlv(out_data, out_len, &tag, &out_digest_len, &out_digest) == 0) {
		/* Failed to parse result */
		return -EIO;
	}

	if (tag != 0x01 && out_digest_len != OPTRUST_SHA256_DIGEST_LEN) {
		/* Invalid data */
		return -EIO;
	}

	memcpy(digest, out_digest, OPTRUST_SHA256_DIGEST_LEN);

	return 0;
}

int optrust_ecdh_calc_ext(struct optrust_ctx *ctx, uint16_t sec_key_oid,
			  enum OPTRUST_ALGORITHM alg,
			  const uint8_t *pub_key, size_t pub_key_len,
			  uint8_t *shared_secret, size_t *shared_secret_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL, "No NULL parameters allowed");
	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U8_LEN + TLV_OVERHEAD + TLV_OVERHEAD;

	if (ctx->apdu_buf_len < cmd_overhead) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	switch (alg) {
	case OPTRUST_ALGORITHM_NIST_P256:
		if (pub_key_len != OPTRUST_NIST_P256_PUB_KEY_LEN) {
			return -EINVAL;
		}
		break;
	case OPTRUST_ALGORITHM_NIST_P384:
		if (pub_key_len != OPTRUST_NIST_P384_PUB_KEY_LEN) {
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID of Private Key */
	tx_buf += set_tlv_u16(tx_buf, 0x01, sec_key_oid);

	/* Algorithm Identifier */
	__ASSERT(alg >= 0 && alg <= UINT8_MAX, "Invalid algorithm identifer");
	tx_buf += set_tlv_u8(tx_buf, 0x05, (uint8_t) alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	uint8_t *pub_key_len_field = tx_buf;

	tx_buf += 2;

	/* Need to subtract TLV_OVERHEAD for the Export Shared Secret field */
	const size_t remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf) - TLV_OVERHEAD;

	/* Public key Value */
	size_t pub_key_asn1_len = set_pub_key_as_bitstring(tx_buf, remaining_apdu_len, pub_key, pub_key_len);

	if (pub_key_asn1_len == 0) {
		/* Encoding error */
		return -EINVAL;
	}
	tx_buf += pub_key_asn1_len;

	/* Public key length know now */
	sys_put_be16(pub_key_asn1_len, pub_key_len_field);

	/* Export Shared Secret */
	tx_buf += set_tlv(tx_buf, 0x07, NULL, 0);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_CALC_SSEC,
					   OPTIGA_TRUSTM_KEY_AGREEMENT_ECDH /* Param */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcSSec Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	const uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len > *shared_secret_len) {
		/* Output buffer too small */
		return -EIO;
	}

	*shared_secret_len = out_len;
	memcpy(shared_secret, out_data, out_len);
	return 0;
}

int optrust_ecdh_calc_oid(struct optrust_ctx *ctx, uint16_t sec_key_oid,
			  enum OPTRUST_ALGORITHM alg,
			  const uint8_t *pub_key, size_t pub_key_len,
			  uint16_t shared_secret_oid)
{
	__ASSERT(ctx != NULL && pub_key != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U8_LEN + TLV_OVERHEAD + SET_TLV_U16_LEN;

	if (ctx->apdu_buf_len < cmd_overhead) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	switch (alg) {
	case OPTRUST_ALGORITHM_NIST_P256:
		if (pub_key_len != OPTRUST_NIST_P256_PUB_KEY_LEN) {
			return -EINVAL;
		}
		break;
	case OPTRUST_ALGORITHM_NIST_P384:
		if (pub_key_len != OPTRUST_NIST_P384_PUB_KEY_LEN) {
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID of Private Key */
	tx_buf += set_tlv_u16(tx_buf, 0x01, sec_key_oid);

	/* Algorithm Identifier */
	__ASSERT(alg >= 0 && alg <= UINT8_MAX, "Invalid algorithm identifer");
	tx_buf += set_tlv_u8(tx_buf, 0x05, (uint8_t) alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	uint8_t *pub_key_len_field = tx_buf;

	tx_buf += 2;

	/* Public key Value */
	size_t remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf) - SET_TLV_U16_LEN;
	size_t pub_key_asn1_len = set_pub_key_as_bitstring(tx_buf, remaining_apdu_len, pub_key, pub_key_len);

	if (pub_key_asn1_len == 0) {
		/* Encoding error */
		return -EINVAL;
	}
	tx_buf += pub_key_asn1_len;

	/* Public key length known now */
	sys_put_be16(pub_key_asn1_len, pub_key_len_field);

	/* OID of Shared Secret */
	tx_buf += set_tlv_u16(tx_buf, 0x08, shared_secret_oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_CALC_SSEC,
					   OPTIGA_TRUSTM_KEY_AGREEMENT_ECDH /* Param */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcSSec Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

int optrust_rng_gen_ext(struct optrust_ctx *ctx, enum OPTRUST_RNG_TYPE type, uint8_t *rnd, size_t rnd_len)
{
	__ASSERT(ctx != NULL && rnd != NULL, "No NULL parameters allowed");
	__ASSERT(rnd_len > 0, "Can't generate 0 random bytes");

	static const size_t cmd_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + 2;

	if (ctx->apdu_buf_len < cmd_len) {
		/* APDU buffer to small */
		return -ENOMEM;
	}

	if (rnd_len > 0x100) {
		/* Requesting too many bytes */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	uint16_t request_len = rnd_len < 8 ? 8 : (uint16_t) rnd_len;

	/* Length of random stream */
	sys_put_be16(request_len, tx_buf);
	tx_buf += 2;

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_GET_RANDOM,
					   (uint8_t) type /* Param */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("GetRandom Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len != request_len) {
		/* Unexpected amount of data */
		return -EIO;
	}

	memcpy(rnd, out_data, rnd_len);
	return 0;
}

int optrust_rng_gen_oid(struct optrust_ctx *ctx, uint16_t oid, size_t rnd_len, const uint8_t *prepend, size_t prepend_len)
{
	__ASSERT(ctx != NULL, "No NULL parameters allowed");
	__ASSERT(rnd_len > 0, "Can't generate 0 random bytes");

	if (prepend == NULL) {
		prepend_len = 0;
	}

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + 2 + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + prepend_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer to small */
		return -ENOMEM;
	}

	if (rnd_len < 0x08 || rnd_len > 0x100) {
		/* Requesting invalid amount of bytes */
		return -EINVAL;
	}

	if (prepend_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Length of random stream */
	sys_put_be16((uint16_t) rnd_len, tx_buf);
	tx_buf += 2;

	/* Optional data to prepend */
	tx_buf += set_tlv(tx_buf, 0x41, prepend, prepend_len);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_GET_RANDOM,
					   0x04 /* Pre-Master Secret */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("GetRandom Error Code: 0x%02x", result_code);
		return -EIO;
	}

	return cmds_check_apdu_empty(ctx);
}

int optrust_rsa_sign_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_SIGNATURE_SCHEME scheme,
			 const uint8_t *digest, size_t digest_len, uint8_t *signature, size_t *signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + digest_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	if (digest_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest to be signed */
	tx_buf += set_tlv(tx_buf, 0x01, digest, (uint16_t) digest_len);

	/* OID of signature key */
	tx_buf += set_tlv_u16(tx_buf, 0x03, oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_CALC_SIGN,
					   (uint8_t) scheme);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcSign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	const uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len != OPTRUST_RSA1024_SIGNATURE_LEN
	    && out_len != OPTRUST_RSA2048_SIGNATURE_LEN) {
		/* Unexpected data */
		return -EIO;
	}

	if (out_len > *signature_len) {
		/* Not enough space in output buffer */
		return -ENOMEM;
	}

	memcpy(signature, out_data, out_len);
	*signature_len = out_len;

	return 0;
}

int optrust_rsa_gen_keys_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_ALGORITHM alg,
			     enum OPTRUST_KEY_USAGE_FLAG key_usage, uint8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL, "No NULL parameters allowed");

	switch (alg) {
	case OPTRUST_ALGORITHM_RSA_1024:        /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_RSA_2048:
		break;
	default:
		return -EINVAL;
	}

	uint8_t *out_data = NULL;
	size_t out_data_len = 0;

	int res = optrust_int_gen_keys_oid(ctx, oid, alg, key_usage, &out_data, &out_data_len);

	if (res != 0) {
		return res;
	}

	uint8_t tag = 0;
	uint16_t len = 0;
	uint8_t *value = NULL;

	if (get_tlv(out_data, out_data_len, &tag, &len, &value) == 0) {
		/* Failed to parse output data */
		return -EIO;
	}

	__ASSERT(tag == 0x02, "Received Key not a pub key");

	if (len > *pub_key_len) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	memcpy(pub_key, value, len);
	*pub_key_len = len;

	return 0;
}

int optrust_rsa_gen_keys_ext(struct optrust_ctx *ctx,
			     enum OPTRUST_ALGORITHM alg,
			     uint8_t *sec_key, size_t *sec_key_len,
			     uint8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL
		 && sec_key != NULL && sec_key_len != NULL, "No NULL parameters allowed");

	switch (alg) {
	case OPTRUST_ALGORITHM_RSA_1024:        /* Intentional fallthrough */
	case OPTRUST_ALGORITHM_RSA_2048:
		break;
	default:
		/* Invalid key algorithm */
		return -EINVAL;
	}

	uint8_t *i_sec_key = NULL;
	size_t i_sec_key_len = 0;

	uint8_t *i_pub_key = NULL;
	size_t i_pub_key_len = 0;

	int res =  optrust_int_gen_keys_ext(ctx, alg, &i_sec_key, &i_sec_key_len,
					    &i_pub_key, &i_pub_key_len);

	if (res != 0) {
		return res;
	}

	/* Check length of output buffers */
	if (i_sec_key_len > *sec_key_len || i_pub_key_len > *pub_key_len) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	/* Copy to output buffers */
	memcpy(sec_key, i_sec_key, i_sec_key_len);
	memcpy(pub_key, i_pub_key, i_pub_key_len);
	*sec_key_len = i_sec_key_len;
	*pub_key_len = i_pub_key_len;

	return 0;
}

int optrust_rsa_verify_ext(struct optrust_ctx *ctx, enum OPTRUST_SIGNATURE_SCHEME scheme,
			   enum OPTRUST_ALGORITHM alg, const uint8_t *pub_key, size_t pub_key_len,
			   const uint8_t *digest, size_t digest_len,
			   const uint8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");
	switch (alg) {
	case OPTRUST_ALGORITHM_RSA_1024:
	case OPTRUST_ALGORITHM_RSA_2048:
		break;
	default:
		/* Invalid public key algorithm */
		return -EINVAL;
	}

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + TLV_OVERHEAD + SET_TLV_U8_LEN + TLV_OVERHEAD;
	const size_t apdu_len = cmd_overhead + pub_key_len + digest_len + signature_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (digest_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	if (signature_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	if (pub_key_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, (uint16_t) digest_len);

	/* Signature */
	tx_buf += set_tlv(tx_buf, 0x02, signature, (uint16_t) signature_len);

	/* Algorithm Identifier of public key */
	__ASSERT(alg >= 0 && alg <= UINT8_MAX, "Invalid algorithm identifer");
	tx_buf += set_tlv_u8(tx_buf, 0x05, (uint8_t) alg);

	/* Public Key */
	tx_buf += set_tlv(tx_buf, 0x06, pub_key, (uint16_t) pub_key_len);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_VERIFY_SIGN,
					   (uint8_t) scheme);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("VerifySign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

int optrust_rsa_verify_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_SIGNATURE_SCHEME scheme,
			   const uint8_t *digest, size_t digest_len, const uint8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + TLV_OVERHEAD + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + digest_len + signature_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (digest_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	if (signature_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, (uint16_t) digest_len);

	/* Signature */
	tx_buf += set_tlv(tx_buf, 0x02, signature, (uint16_t) signature_len);

	/* OID of Public Key Certificate */
	tx_buf += set_tlv_u16(tx_buf, 0x04, oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_VERIFY_SIGN,
					   (uint8_t) scheme);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("VerifySign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* No response data expected */
	return cmds_check_apdu_empty(ctx);
}

int optrust_tls1_2_prf_sha256_calc_oid(struct optrust_ctx *ctx, uint16_t sec_oid, const uint8_t *deriv_data, size_t deriv_data_len,
				       size_t key_len, uint16_t key_oid)
{
	__ASSERT(ctx != NULL && deriv_data != NULL, "No NULL parameters allowed");
	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U8_LEN + TLV_OVERHEAD + SET_TLV_U16_LEN + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + deriv_data_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (deriv_data_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	if (key_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID of Shared Secret */
	tx_buf += set_tlv_u16(tx_buf, 0x01, sec_oid);

	/* Secret derivation data */
	tx_buf += set_tlv(tx_buf, 0x02, deriv_data, (uint16_t) deriv_data_len);

	/* Length of derived key */
	tx_buf += set_tlv_u16(tx_buf, 0x03, (uint16_t) key_len);

	/* OID to store the derived key */
	tx_buf += set_tlv_u16(tx_buf, 0x08, key_oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_DERIVE_KEY,
					   0x01 /* TLS PRF SHA256 according to [RFC5246] */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("DeriveKey Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	return cmds_check_apdu_empty(ctx);
}

int optrust_tls1_2_prf_sha256_calc_ext(struct optrust_ctx *ctx, uint16_t sec_oid, const uint8_t *deriv_data, size_t deriv_data_len,
				       uint8_t *key, size_t key_len)
{
	__ASSERT(ctx != NULL && deriv_data != NULL, "No NULL parameters allowed");
	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U8_LEN + TLV_OVERHEAD + SET_TLV_U16_LEN + TLV_OVERHEAD;
	const size_t apdu_len = cmd_overhead + deriv_data_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (key_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	if (deriv_data_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID of Shared Secret */
	tx_buf += set_tlv_u16(tx_buf, 0x01, sec_oid);

	/* Secret derivation data */
	tx_buf += set_tlv(tx_buf, 0x02, deriv_data, (uint16_t) deriv_data_len);

	/* Length of derived key */
	tx_buf += set_tlv_u16(tx_buf, 0x03, (uint16_t) key_len);

	/* Export derived key */
	tx_buf += set_tlv(tx_buf, 0x07, NULL, 0);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_DERIVE_KEY,
					   0x01 /* TLS PRF SHA256 according to [RFC5246] */);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("DeriveKey Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	const uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len != key_len) {
		/* Unexpected outData */
		return -EIO;
	}

	memcpy(key, out_data, out_len);

	return 0;
}

/**
 * @brief Internal function to submit and parse the result of an EncryptAsym command
 *
 * @param ctx Command context to use
 * @param tx_buf First free element in transmit buffer
 * @param enc_msg Output buffer for the encrypted message
 * @param enc_msg_len Length of enc_msg, contains written bytes afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_int_rsa_encrypt_submit(struct optrust_ctx *ctx, uint8_t *tx_buf, uint8_t *enc_msg, size_t *enc_msg_len)
{
	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_ENCRYPT_ASYM,
					   OPTIGA_TRUSTM_ASYM_CIPHER_RSAES_PKCS1_1_5);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("EncryptAsym Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	uint8_t tag = 0;
	uint16_t len = 0;
	uint8_t *value = NULL;

	if (get_tlv(out_data, out_len, &tag, &len, &value) == 0) {
		/* Invalid data */
		return -EIO;
	}

	if (tag != 0x61) {
		/* Invalid data */
		return -EIO;
	}

	if (len > *enc_msg_len) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	memcpy(enc_msg, value, len);
	*enc_msg_len = len;

	return 0;
}

int optrust_rsa_encrypt_msg_ext(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				enum OPTRUST_ALGORITHM alg, const uint8_t *pub_key, size_t pub_key_len,
				uint8_t *enc_msg, size_t *enc_msg_len)
{
	__ASSERT(ctx != NULL && msg != NULL && pub_key != NULL && enc_msg != NULL, "No NULL parameters allowed");
	switch (alg) {
	case OPTRUST_ALGORITHM_RSA_1024:
	case OPTRUST_ALGORITHM_RSA_2048:
		break;
	default:
		/* Invalid public key algorithm */
		return -EINVAL;
	}

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + SET_TLV_U8_LEN + TLV_OVERHEAD;
	const size_t apdu_len = cmd_overhead + msg_len + pub_key_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (msg_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	if (pub_key_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Message */
	tx_buf += set_tlv(tx_buf, 0x61, msg, msg_len);

	/* Algorithm Identifier of public key*/
	tx_buf += set_tlv_u8(tx_buf, 0x05, (uint8_t) alg);

	/* Public Key */
	tx_buf += set_tlv(tx_buf, 0x06, pub_key, pub_key_len);

	return optrust_int_rsa_encrypt_submit(ctx, tx_buf, enc_msg, enc_msg_len);
}

int optrust_rsa_encrypt_oid_ext(struct optrust_ctx *ctx, uint16_t oid,
				enum OPTRUST_ALGORITHM alg, const uint8_t *pub_key, size_t pub_key_len,
				uint8_t *enc_msg, size_t *enc_msg_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && enc_msg != NULL, "No NULL parameters allowed");
	switch (alg) {
	case OPTRUST_ALGORITHM_RSA_1024:
	case OPTRUST_ALGORITHM_RSA_2048:
		break;
	default:
		/* Invalid public key algorithm */
		return -EINVAL;
	}

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U8_LEN + TLV_OVERHEAD;
	const size_t apdu_len = cmd_overhead + pub_key_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (pub_key_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	tx_buf += set_tlv_u16(tx_buf, 0x02, oid);

	/* Algorithm Identifier of public key*/
	tx_buf += set_tlv_u8(tx_buf, 0x05, (uint8_t) alg);

	/* Public Key */
	tx_buf += set_tlv(tx_buf, 0x06, pub_key, pub_key_len);

	return optrust_int_rsa_encrypt_submit(ctx, tx_buf, enc_msg, enc_msg_len);
}

int optrust_rsa_encrypt_msg_oid(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				uint16_t cert_oid, uint8_t *enc_msg, size_t *enc_msg_len)
{
	__ASSERT(ctx != NULL && msg != NULL && enc_msg != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + msg_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (msg_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Message */
	tx_buf += set_tlv(tx_buf, 0x61, msg, msg_len);

	/* Public Key Certificate OID */
	tx_buf += set_tlv_u16(tx_buf, 0x04, cert_oid);

	return optrust_int_rsa_encrypt_submit(ctx, tx_buf, enc_msg, enc_msg_len);
}

int optrust_rsa_encrypt_oid_oid(struct optrust_ctx *ctx, uint16_t msg_oid,
				uint16_t cert_oid, uint8_t *enc_msg, size_t *enc_msg_len)
{
	__ASSERT(ctx != NULL && enc_msg != NULL, "No NULL parameters allowed");

	static const size_t cmd_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U16_LEN;

	if (ctx->apdu_buf_len < cmd_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Message OID */
	tx_buf += set_tlv_u16(tx_buf, 0x02, msg_oid);

	/* Public Key Certificate OID */
	tx_buf += set_tlv_u16(tx_buf, 0x04, cert_oid);

	return optrust_int_rsa_encrypt_submit(ctx, tx_buf, enc_msg, enc_msg_len);
}

int optrust_rsa_decrypt_msg_oid(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				uint16_t key_oid,  uint8_t *dec_msg, size_t *dec_msg_len)
{
	__ASSERT(ctx != NULL && msg != NULL && dec_msg != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + msg_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (msg_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Protected Message */
	tx_buf += set_tlv(tx_buf, 0x61, msg, msg_len);

	/* Private key OID */
	tx_buf += set_tlv_u16(tx_buf, 0x03, key_oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_DECRYPT_ASYM,
					   OPTIGA_TRUSTM_ASYM_CIPHER_RSAES_PKCS1_1_5);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("DecryptAsym Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	uint16_t out_len = 0;
	uint8_t *out_data = cmds_check_apdu(ctx, &out_len);

	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	uint8_t tag = 0;
	uint16_t len = 0;
	uint8_t *value = NULL;

	if (get_tlv(out_data, out_len, &tag, &len, &value) == 0) {
		/* Invalid data */
		return -EIO;
	}

	if (tag != 0x61) {
		/* Invalid data */
		return -EIO;
	}

	if (len > *dec_msg_len) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	memcpy(dec_msg, value, len);
	*dec_msg_len = len;

	return 0;
}

int optrust_rsa_decrypt_oid_oid(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				uint16_t key_oid,  uint16_t dec_oid)
{
	__ASSERT(ctx != NULL && msg != NULL, "No NULL parameters allowed");

	static const size_t cmd_overhead = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + SET_TLV_U16_LEN + SET_TLV_U16_LEN;
	const size_t apdu_len = cmd_overhead + msg_len;

	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	if (msg_len > UINT16_MAX) {
		/* Overflow in length field */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	uint8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Protected Message */
	tx_buf += set_tlv(tx_buf, 0x61, msg, msg_len);

	/* Private key OID */
	tx_buf += set_tlv_u16(tx_buf, 0x03, key_oid);

	/* OID to store decrypted data */
	tx_buf += set_tlv_u16(tx_buf, 0x02, key_oid);

	int result_code = cmds_submit_apdu(ctx,
					   tx_buf,
					   OPTIGA_TRUSTM_CMD_DECRYPT_ASYM,
					   OPTIGA_TRUSTM_ASYM_CIPHER_RSAES_PKCS1_1_5);

	if (optiga_is_driver_error(result_code)) {
		/* Our driver errored */
		return result_code;
	} else if (optiga_is_device_error(result_code)) {
		/* OPTIGA produced an error code */
		LOG_INF("DecryptAsym Error Code: 0x%02x", result_code);
		return -EIO;
	}

	return cmds_check_apdu_empty(ctx);
}