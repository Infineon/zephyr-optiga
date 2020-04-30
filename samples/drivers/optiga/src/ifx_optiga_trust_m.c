/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/crypto/optiga.h>
#include <sys/byteorder.h>

#include "ifx_optiga_trust_m.h"
#include "ecdsa_utils.h"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(cmds_m);

#define U16_MAX (0xFFFF)

enum OPTIGA_TRUSTM_CMD {
	OPTIGA_TRUSTM_CMD_GET_DATA_OBJECT =	0x81,
	OPTIGA_TRUSTM_CMD_SET_DATA_OBJECT =	0x82,
	OPTIGA_TRUSTM_CMD_GET_RANDOM =		0x8C,
	OPTIGA_TRUSTM_CMD_CALC_HASH =		0xB0,
	OPTIGA_TRUSTM_CMD_CALC_SIGN =		0xB1,
	OPTIGA_TRUSTM_CMD_VERIFY_SIGN =		0xB2,
	OPTIGA_TRUSTM_CMD_CALC_SSEC =		0xB3,
	OPTIGA_TRUSTM_CMD_DERIVE_KEY =		0xB4,
	OPTIGA_TRUSTM_CMD_GEN_KEYPAIR =		0xB8,
};

/* Parameters for SetDataObject command, see Table 9 */
enum OPTIGA_TRUSTM_SET_DATA_OBJECT {
	OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_DATA = 0x00,
	OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_METADATA = 0x01,
	OPTIGA_TRUSTM_SET_DATA_OBJECT_ERASE_WRITE_DATA = 0x40,
};

/* Key Agreement Schemes, see Table 24 */
#define OPTIGA_TRUSTM_KEY_AGREEMENT_ECDH 0x01

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

#define TLV_TAG_LEN 1
#define TLV_LEN_LEN 2

#define TLV_TAG_OFFS 0
#define TLV_LEN_OFFS (TLV_TAG_OFFS + TLV_TAG_LEN)
#define TLV_VAL_OFFS (TLV_LEN_OFFS + TLV_LEN_LEN)

#define TLV_OVERHEAD (TLV_TAG_LEN + TLV_LEN_LEN)

/**
 * @brief Encodes bytes into a Tag Length Value structure
 * @param buf Target buffer for encoded data
 * @param tag Tag value
 * @param val Buffer for Value bytes
 * @param val_len Length of val
 * @return Number of bytes written
 * @note This function does not check for buffer overflow or overflow in Length field
 */
static size_t set_tlv(u8_t *buf, u8_t tag, const u8_t *val, size_t val_len)
{
	buf[TLV_TAG_OFFS] = tag;
	sys_put_be16(val_len, &buf[TLV_LEN_OFFS]);
	memcpy(&buf[TLV_VAL_OFFS], val, val_len);
	return val_len + TLV_OVERHEAD;
}

#define SET_TLV_U8_LEN 4
static size_t set_tlv_u8(u8_t *buf, u8_t tag, u8_t val)
{
	buf[TLV_TAG_OFFS] = tag;
	sys_put_be16(1, &buf[TLV_LEN_OFFS]);
	buf[TLV_VAL_OFFS] = val;
	return SET_TLV_U8_LEN;
}

#define SET_TLV_U16_LEN 5
static size_t set_tlv_u16(u8_t *buf, u8_t tag, u16_t val)
{
	buf[TLV_TAG_OFFS] = tag;
	sys_put_be16(2, &buf[TLV_LEN_OFFS]);
	sys_put_be16(val, &buf[TLV_VAL_OFFS]);
	return SET_TLV_U16_LEN;
}

static bool get_tlv(u8_t *buf, size_t buf_len, u8_t *tag, u16_t *len, u8_t** value)
{
	if(buf == NULL) {
		return false;
	}

	if (buf_len < TLV_OVERHEAD) {
		return false;
	}

	u8_t *tlv_start = buf;

	if (tag) {
		*tag = *tlv_start;
	}
	tlv_start += TLV_TAG_LEN;

	u16_t tlv_len = sys_get_be16(tlv_start);
	if (tlv_len > (buf_len - TLV_OVERHEAD)) {
		/* Value field longer than buffer */
		return false;
	}

	if (len) {
		*len = tlv_len;
	}

	tlv_start += TLV_LEN_LEN;
	if(value) {
		*value = tlv_start;
	}

	return true;
}



#define DER_TAG_BITSTRING 0x03
#define DER_TAG_OCTET_STRING 0x04
/* Tag + Length + Unused bits field */
#define DER_BITSTRING_OVERHEAD 3
/* DER BITSTRING encoding overhead  + Compressed point marker */
#define DER_BITSTRING_PK_OVERHEAD (DER_BITSTRING_OVERHEAD + 1)
/* For encoding length in a single byte */
#define DER_LENGTH_SINGLE_MAX 127

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
static size_t set_pub_key_as_bitstring(u8_t *buf, size_t buf_len, const u8_t *pub_key, size_t pub_key_len)
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
	*buf = 0x04;
	buf++;

	/* actual data */
	memcpy(buf, pub_key, pub_key_len);
	return pub_key_len + DER_BITSTRING_PK_OVERHEAD;
}

static size_t cmds_set_apdu_header(u8_t *apdu_start, enum OPTIGA_TRUSTM_CMD cmd, u8_t param, u16_t in_len)
{
	apdu_start[OPTIGA_TRUSTM_CMD_OFFSET] = cmd;
	apdu_start[OPTIGA_TRUSTM_PARAM_OFFSET] = param;
	sys_put_be16(in_len, &apdu_start[OPTIGA_TRUSTM_IN_LEN_OFFSET]);
	return OPTIGA_TRUSTM_IN_DATA_OFFSET;
}

static size_t cmds_get_apdu_header(const u8_t *apdu_start, u8_t *sta, u16_t *out_len)
{
	if (sta) {
		*sta = apdu_start[OPTIGA_TRUSTM_STA_OFFSET];
	}

	if (out_len) {
		*out_len = sys_get_be16(&apdu_start[OPTIGA_TRUSTM_OUT_LEN_OFFSET]);
	}

	return OPTIGA_TRUSTM_IN_DATA_OFFSET;
}


int optrust_init(struct optrust_ctx *ctx, struct device *dev, u8_t *apdu_buf, size_t apdu_buf_len)
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

static int cmds_submit_apdu(struct optrust_ctx *ctx, const u8_t *apdu_end, enum OPTIGA_TRUSTM_CMD cmd, u8_t param)
{
	const u8_t *apdu_start = ctx->apdu_buf;
	__ASSERT((apdu_start + OPTIGA_TRUSTM_IN_DATA_OFFSET)  <= apdu_end, "Invalid apdu_end pointer");

	const size_t in_data_len = apdu_end - apdu_start - OPTIGA_TRUSTM_IN_DATA_OFFSET;

	if (in_data_len > U16_MAX) {
		/* Overflow in inData field */
		return -EINVAL;
	}

	cmds_set_apdu_header(ctx->apdu_buf, cmd, param, (u16_t) in_data_len);

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
static u8_t* cmds_check_apdu(struct optrust_ctx *ctx, size_t *out_len)
{
	__ASSERT(ctx != NULL && out_len != NULL, "No NULL parameters allowed");

	/* need at least the 4 bytes of response data */
	if (ctx->apdu.rx_len < OPTIGA_TRUSTM_OUT_DATA_OFFSET) {
		LOG_ERR("Malformed APDU");
		return NULL;
	}

	u8_t *rx_buf = ctx->apdu.rx_buf;

	u8_t sta = 0;
	u16_t len = 0;
	rx_buf += cmds_get_apdu_header(rx_buf, &sta, &len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	/* Ensure length of APDU and length of buffer match */
	if (len != (ctx->apdu.rx_len - OPTIGA_TRUSTM_OUT_DATA_OFFSET)) {
		LOG_ERR("Incomplete APDU");
		return NULL;
	}

	*out_len = len;

	return rx_buf;
}

/* Must be synced to OPTIGA_IGNORE_HIBERNATE in crypto_optiga.h */
#define OPTIGA_TRUSTM_WAKE_LOCK_IDX_START 8
#define OPTIGA_TRUSTM_WAKE_LOCK_IDX_END 32

int optrust_wake_lock_acquire(struct optrust_ctx *ctx, int *token)
{
	__ASSERT(ctx != NULL && token != NULL, "No NULL parameters allowed");

	int session = OPTIGA_TRUSTM_WAKE_LOCK_IDX_START;
	for(; session < OPTIGA_TRUSTM_WAKE_LOCK_IDX_END; session++) {
		bool acquired = optiga_session_acquire(ctx->dev, session);
		if(acquired) {
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
static const u16_t optiga_trustm_sessions[OPTIGA_TRUSTM_SESSIONS] = {
	0xE100,
	0xE101,
	0xE102,
	0xE103,
};

int optrust_session_acquire(struct optrust_ctx *ctx, u16_t *oid)
{
	int session = 0;
	for(; session < OPTIGA_TRUSTM_SESSIONS; session++) {
		bool acquired = optiga_session_acquire(ctx->dev, session);
		if(acquired) {
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

int optrust_session_release(struct optrust_ctx *ctx, u16_t oid)
{
	int session = 0;
	for(; session < OPTIGA_TRUSTM_SESSIONS; session++) {
		if(oid == optiga_trustm_sessions[session]) {
			optiga_session_release(ctx->dev, session);
			return 0;
		}
	}

	/* Invalid OID */
	return -EINVAL;
}

int optrust_shielded_connection_psk_start(struct optrust_ctx *ctx, const u8_t *psk, size_t psk_len)
{
	__ASSERT(ctx != NULL && psk != NULL, "No NULL parameters allowed");

	/* Tell driver to enable shielded connection */
	int res = optiga_start_shield(ctx->dev, psk, psk_len);
	if (res != 0) {
		return res;
	}

	/* Submit a dummy APDU to trigger an immediate handshake */
	u8_t dummy = 0;
	size_t dummy_len = 1;
	/* If that APDU fails, it's because shielded connection was not enabled properly */
	return optrust_data_get(ctx, 0xE0C2, 0, &dummy, &dummy_len);
}



#define OPTIGA_GET_DATA_CMD_LEN (OPTIGA_TRUSTM_IN_DATA_OFFSET + 6)
int optrust_data_get(struct optrust_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len)
{
	__ASSERT(ctx != NULL && buf != NULL && len != NULL, "No NULL parameters allowed");

	if (offs > U16_MAX || *len > U16_MAX) {
		/* Prevent overflow in parameter encoding */
		return -EINVAL;
	}

	if (ctx->apdu_buf_len < OPTIGA_GET_DATA_CMD_LEN) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

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
	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("GetDataObject Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);

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

#define OPTIGA_GET_METADATA_CMD_LEN (OPTIGA_TRUSTM_IN_DATA_OFFSET + 2)
int optrust_metadata_get(struct optrust_ctx *ctx, u16_t oid, u8_t *buf, size_t *len)
{
	__ASSERT(ctx != NULL && buf != NULL && len != NULL, "No NULL parameters allowed");

	if (ctx->apdu_buf_len < OPTIGA_GET_DATA_CMD_LEN) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	int result_code = cmds_submit_apdu(ctx,
						tx_buf,
						OPTIGA_TRUSTM_CMD_GET_DATA_OBJECT,
						0x01 /* Read metadata */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("GetDataObject Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
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

#define OPTIGA_SET_DATA_CMD_OVERHEAD (OPTIGA_TRUSTM_IN_DATA_OFFSET + 4)
int optrust_data_set(struct optrust_ctx *ctx, u16_t oid, bool erase, size_t offs, const u8_t *buf, size_t len)
{
	__ASSERT(ctx != NULL && buf != NULL, "No NULL parameters allowed");

	if (offs > U16_MAX) {
		/* Prevent overflow in parameter encoding */
		return -EINVAL;
	}

	const size_t apdu_len = OPTIGA_SET_DATA_CMD_OVERHEAD + len;
	if (apdu_len > ctx->apdu_buf_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	const u8_t param = erase ? OPTIGA_TRUSTM_SET_DATA_OBJECT_ERASE_WRITE_DATA
		: OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_DATA;

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Data */
	memcpy(tx_buf, buf, len);
	tx_buf += len;

	int result_code = cmds_submit_apdu(ctx,
						tx_buf,
						OPTIGA_TRUSTM_CMD_SET_DATA_OBJECT,
						param /* Param */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("SetDataObject Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Still need to check return data */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len != 0) {
		/* We don't expect any return data here */
		return -EIO;
	}

	return 0;
}

#define OPTIGA_ECDSA_SIGN_OID_OVERHEAD (OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + SET_TLV_U16_LEN)
int optrust_ecdsa_sign_oid(struct optrust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");

	const size_t apdu_len = OPTIGA_ECDSA_SIGN_OID_OVERHEAD + digest_len;
	if (apdu_len > ctx->apdu_buf_len) {
		/* Prevent overflow in APDU buffer */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest to be signed */
	tx_buf += set_tlv(tx_buf, 0x01, digest, digest_len);

	/* OID of signature key */
	tx_buf += set_tlv_u16(tx_buf, 0x03, oid);

	int result_code = cmds_submit_apdu(ctx,
						tx_buf,
						OPTIGA_TRUSTM_CMD_CALC_SIGN,
						0x11 /* ECDSA FIPS 186-3 w/o hash */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcSign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	/* decode to raw RS values */
	bool success = asn1_to_ecdsa_rs(out_data, out_len, signature, signature_len);
	if(!success) {
		LOG_ERR("Failed to decode signature");
		return -EIO;
	}

	return 0;
}

#define OPTIGA_ECDSA_VERIFY_EXT_OVERHEAD (OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + TLV_OVERHEAD + SET_TLV_U16_LEN)
int optrust_ecdsa_verify_ext(struct optrust_ctx *ctx, enum OPTRUST_ALGORITHM alg,
				const u8_t *pub_key, size_t pub_key_len,
				const u8_t *digest, size_t digest_len,
				const u8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");

	switch(alg) {
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

	const size_t apdu_block_1_len = OPTIGA_ECDSA_VERIFY_EXT_OVERHEAD + digest_len;
	if (apdu_block_1_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, digest_len);

	/* Second parameter */
	*tx_buf = 0x02;
	tx_buf++;

	/* we don't know the length of the signature data and public key yet, remember the position */
	u8_t * const sig_len_field = tx_buf;
	tx_buf += 2;

	/* Signature */

	size_t remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf) - SET_TLV_U16_LEN;
	size_t asn1_sig_len = remaining_apdu_len;

	__ASSERT((signature_len % 2) == 0, "Signature must have even number of bytes");
	bool success = ecdsa_rs_to_asn1_integers(signature, signature + signature_len/2, signature_len/2, tx_buf, &asn1_sig_len);
	if(!success) {
		LOG_ERR("Couldn't encode signature");
		return -EINVAL;
	}
	tx_buf += asn1_sig_len;

	if (asn1_sig_len > U16_MAX) {
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
	tx_buf += set_tlv_u8(tx_buf, 0x05, alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	u8_t *pub_key_len_field = tx_buf;
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
						0x11 /* ECDSA FIPS 186-3 w/o hash */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("VerifySign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len != 0) {
		/* Unexpected outData */
		return -EIO;
	}

	return 0;
}

#define OPTIGA_ECDSA_VERIFY_OID_OVERHEAD (OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + TLV_OVERHEAD + SET_TLV_U16_LEN)
int optrust_ecdsa_verify_oid(struct optrust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, const u8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");
	const size_t apdu_block_1_len = OPTIGA_ECDSA_VERIFY_OID_OVERHEAD + digest_len;
	if (apdu_block_1_len > ctx->apdu_buf_len) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, digest_len);

	/* Second parameter */
	*tx_buf = 0x02;
	tx_buf++;

	/* we don't know the length of the signature data yet, remember the position */
	u8_t * const sig_len_field = tx_buf;
	tx_buf += 2;

	/* Signature */
	size_t remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf) - SET_TLV_U16_LEN;
	size_t asn1_sig_len = remaining_apdu_len;

	__ASSERT((signature_len % 2) == 0, "Signature must have even number of bytes");
	bool success = ecdsa_rs_to_asn1_integers(signature, signature + signature_len/2, signature_len/2, tx_buf, &asn1_sig_len);
	if(!success) {
		LOG_ERR("Couldn't encode signature");
		return -EINVAL;
	}
	tx_buf += asn1_sig_len;

	if (asn1_sig_len > U16_MAX) {
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
						0x11 /* ECDSA FIPS 186-3 w/o hash */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("VerifySign Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	if (out_len != 0) {
		/* Unexpected outData */
		return -EIO;
	}

	return 0;
}

#define OPTIGA_ECC_GEN_KEYS_OID_LEN (OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U8_LEN)
int optrust_ecc_gen_keys_oid(struct optrust_ctx *ctx, u16_t oid, enum OPTRUST_ALGORITHM alg,
                enum OPTRUST_KEY_USAGE_FLAG key_usage, u8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL, "No NULL parameters allowed");

	switch(alg) {
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

	if (ctx->apdu_buf_len < OPTIGA_ECC_GEN_KEYS_OID_LEN) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID */
	tx_buf += set_tlv_u16(tx_buf, 0x01, oid);

	/* Key usage identifier */
	tx_buf += set_tlv_u8(tx_buf, 0x02, key_usage);

	int result_code = cmds_submit_apdu(ctx,
						tx_buf,
						OPTIGA_TRUSTM_CMD_GEN_KEYPAIR,
						alg /* Key algorithm */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("GenKeyPair Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	__ASSERT(out_data[0] == 0x02, "Received Key not a pub key");

	// TODO(chr): decide if we can skip ASN.1 decoding
	/* the following decoding routine only works if the public key has a fixed length */
	__ASSERT(out_len == (*pub_key_len + 7), "Assumption about pub key encoding was wrong");
	out_data += 3; // skip tag and length
	out_data += 4; // skip ASN.1 tag, length and 2 value bytes
	memcpy(pub_key, out_data, *pub_key_len);

	return 0;
}

#define OPTIGA_ECC_GEN_KEYS_EXT_LEN (OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD)
int optrust_ecc_gen_keys_ext(struct optrust_ctx *ctx,
				enum OPTRUST_ALGORITHM alg,
				u8_t *sec_key, size_t *sec_key_len,
				u8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL
		&& sec_key != NULL && sec_key_len != NULL, "No NULL parameters allowed");

	switch(alg) {
        case OPTRUST_ALGORITHM_NIST_P256:
		if (*pub_key_len < OPTRUST_NIST_P256_PUB_KEY_LEN
			|| *sec_key_len < OPTRUST_NIST_P256_SEC_KEY_LEN) {
			return -EINVAL;
		}

		*sec_key_len = OPTRUST_NIST_P256_SEC_KEY_LEN;
		*pub_key_len = OPTRUST_NIST_P256_PUB_KEY_LEN;
	break;
        case OPTRUST_ALGORITHM_NIST_P384:
		if(*pub_key_len < OPTRUST_NIST_P384_PUB_KEY_LEN
			|| *sec_key_len < OPTRUST_NIST_P384_SEC_KEY_LEN) {
			return -EINVAL;
		}

		*sec_key_len = OPTRUST_NIST_P384_SEC_KEY_LEN;
		*pub_key_len = OPTRUST_NIST_P384_PUB_KEY_LEN;
		break;
	default:
		return -EINVAL;
	}

	if (ctx->apdu_buf_len < OPTIGA_ECC_GEN_KEYS_EXT_LEN) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Export key pair in plain */
	tx_buf += set_tlv(tx_buf, 0x07, NULL, 0);

	int result_code = cmds_submit_apdu(ctx,
						tx_buf,
						OPTIGA_TRUSTM_CMD_GEN_KEYPAIR,
						alg /* Key algorithm */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("GenKeyPair Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	// TODO(chr): more robust ASN.1 decoding

	u8_t tag = 0;
	u16_t len = 0;
	u8_t *sec_key_asn1 = NULL;

	/* Parse secrect key */
	bool res = get_tlv(out_data, out_len, &tag, &len, &sec_key_asn1);
	if (!res) {
		/* Failed to parse TLV data structure */
		return -EIO;
	}

	if (tag != 0x01) {
		/* Unexpected Tag */
		return -EIO;
	}

	/* Secret key is encoded as DER OCTET STRING */

	/* ASN.1 encoding overhead are 2 bytes */
	if (len != (*sec_key_len + 2)) {
		/* Unexpected length */
		return -EIO;
	}

	__ASSERT(sec_key_asn1[0] == DER_TAG_OCTET_STRING, "Not an DER OCTECT STRING");
	__ASSERT(sec_key_asn1[1] == *sec_key_len, "Length mismatch");

	sec_key_asn1 += 2;
	memcpy(sec_key, sec_key_asn1, *sec_key_len);

	/* Parse public key */
	out_data = sec_key_asn1 + *sec_key_len;
	out_len -= len;

	u8_t *pub_key_asn1 = NULL;
	res = get_tlv(out_data, out_len, &tag, &len, &pub_key_asn1);
	if (!res) {
		/* Failed to parse TLV data structure */
		return -EIO;
	}

	if (tag != 0x02) {
		/* Unexpected Tag */
		return -EIO;
	}

	/* Public key is encoded as DER BIT STRING */

	/* ASN.1 encoding overhead are 4 bytes */
	if (len != (*pub_key_len + 4)) {
		/* Unexpected length */
		return -EIO;
	}

	__ASSERT(pub_key_asn1[0] == 0x03, "Not an DER BIT STRING");
	__ASSERT(pub_key_asn1[1] == (*pub_key_len + 2), "Length mismatch");
	__ASSERT(pub_key_asn1[2] == 0, "Unused bits encoding not supported");
	__ASSERT(pub_key_asn1[3] == 0x04, "Not a compressed point");

	pub_key_asn1 += 4; /* 1 byte TAG, 1 byte Length, 1 byte for unused bits, 1 for "compressed point" indicator */
	memcpy(pub_key, pub_key_asn1, *pub_key_len);

	return 0;
}

/* Tags for CalcHash command, see Table 16 */
enum OPTIGA_TRUSTM_CALC_HASH_TAGS {
	OPTIGA_TRUSTM_CALC_HASH_START = 0x00,
	OPTIGA_TRUSTM_CALC_HASH_START_FINAL = 0x01,
	OPTIGA_TRUSTM_CALC_HASH_CONTINUE = 0x02,
	OPTIGA_TRUSTM_CALC_HASH_FINAL = 0x03,
	OPTIGA_TRUSTM_CALC_HASH_TERMINATE = 0x04,
	OPTIGA_TRUSTM_CALC_HASH_FINAL_KEEP = 0x05,
	OPTIGA_TRUSTM_CALC_HASH_OID_START = 0x10,
	OPTIGA_TRUSTM_CALC_HASH_OID_START_FINAL = 0x11,
	OPTIGA_TRUSTM_CALC_HASH_OID_CONTINUE = 0x12,
	OPTIGA_TRUSTM_CALC_HASH_OID_FINAL = 0x13,
	OPTIGA_TRUSTM_CALC_HASH_OID_FINAL_KEEP = 0x15,
};

int optrust_sha256_ext(struct optrust_ctx *ctx, const u8_t* data, size_t data_len,
                       u8_t *digest, size_t *digest_len)
{
	__ASSERT(ctx != NULL && digest != NULL && digest_len != NULL && data != NULL, "No NULL parameters allowed");

	const size_t apdu_len = OPTIGA_TRUSTM_IN_DATA_OFFSET + TLV_OVERHEAD + data_len;
	if (apdu_len > ctx->apdu_buf_len) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	if (*digest_len < OPTRUST_SHA256_DIGEST_LEN) {
		/* Output buffer too small */
		return -ENOMEM;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Write message data */
	tx_buf += set_tlv(tx_buf, OPTIGA_TRUSTM_CALC_HASH_START_FINAL, data, data_len);

	int result_code = cmds_submit_apdu(ctx,
						tx_buf,
						OPTIGA_TRUSTM_CMD_CALC_HASH,
						OPTRUST_ALGORITHM_SHA256 /* Param */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcHash Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	__ASSERT(out_len == (OPTRUST_SHA256_DIGEST_LEN + TLV_OVERHEAD), "Unexpected data returned");

	u8_t tag = 0;
	u16_t len = 0;
	u8_t *out_digest = NULL;
	if (!get_tlv(out_data, out_len, &tag, &len, &out_digest)) {
		/* Failed to parse result */
		return -EIO;
	}

	if (tag != 0x01 && len != OPTRUST_SHA256_DIGEST_LEN ) {
		/* Invalid data */
		return -EIO;
	}

	memcpy(digest, out_digest, OPTRUST_SHA256_DIGEST_LEN);

	return 0;
}

#define OPTIGA_SHA256_OID_LEN (OPTIGA_TRUSTM_IN_DATA_OFFSET + 9)
int optrust_sha256_oid(struct optrust_ctx *ctx,
				u16_t oid, size_t offs, size_t len,
				u8_t *digest, size_t *digest_len)
{
	__ASSERT(ctx != NULL && digest != NULL && digest_len != NULL, "No NULL parameters allowed");

	if (offs > UINT16_MAX || len > UINT16_MAX) {
		/* Overflow in Offset or Length field */
		return -EINVAL;
	}

	if (OPTIGA_SHA256_OID_LEN > ctx->apdu_buf_len) {
		/* APDU buffer too small */
		return -ENOMEM;
	}

	if (*digest_len < OPTRUST_SHA256_DIGEST_LEN) {
		/* Output buffer too small */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

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

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcHash Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	__ASSERT(out_len == (OPTRUST_SHA256_DIGEST_LEN + 3), "Unexpected data returned");

	u8_t tag = 0;
	u16_t out_digest_len = 0;
	u8_t *out_digest = NULL;
	if (!get_tlv(out_data, out_len, &tag, &out_digest_len, &out_digest)) {
		/* Failed to parse result */
		return -EIO;
	}

	if (tag != 0x01 && out_digest_len != OPTRUST_SHA256_DIGEST_LEN ) {
		/* Invalid data */
		return -EIO;
	}

	memcpy(digest, out_digest, OPTRUST_SHA256_DIGEST_LEN);

	return 0;
}

#define OPTIGA_ECDH_CALC_EXT_OVERHEAD (OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U8_LEN + TLV_OVERHEAD + TLV_OVERHEAD)
int optrust_ecdh_calc_ext(struct optrust_ctx *ctx, u16_t sec_key_oid,
				enum OPTRUST_ALGORITHM alg,
				const u8_t *pub_key, size_t pub_key_len,
				u8_t* shared_secret, size_t* shared_secret_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL, "No NULL parameters allowed");

	if (ctx->apdu_buf_len < OPTIGA_ECDH_CALC_EXT_OVERHEAD) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	switch(alg) {
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
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID of Private Key */
	tx_buf += set_tlv_u16(tx_buf, 0x01, sec_key_oid);

	/* Algorithm Identifier */
	tx_buf += set_tlv_u8(tx_buf, 0x05, alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	u8_t *pub_key_len_field = tx_buf;
	tx_buf += 2;

	/* Public key Value */
	const size_t remaining_apdu_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf) - TLV_OVERHEAD;
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

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcSSec Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
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

#define OPTIGA_ECDH_CALC_OID_OVERHEAD (OPTIGA_TRUSTM_IN_DATA_OFFSET + SET_TLV_U16_LEN + SET_TLV_U8_LEN + TLV_OVERHEAD + SET_TLV_U16_LEN)
int optrust_ecdh_calc_oid(struct optrust_ctx *ctx, u16_t sec_key_oid,
				enum OPTRUST_ALGORITHM alg,
				const u8_t *pub_key, size_t pub_key_len,
				u16_t shared_secret_oid)
{
	__ASSERT(ctx != NULL && pub_key != NULL, "No NULL parameters allowed");

	if (ctx->apdu_buf_len < OPTIGA_ECDH_CALC_OID_OVERHEAD) {
		/* APDU buffer not big enough */
		return -ENOMEM;
	}

	switch(alg) {
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
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID of Private Key */
	tx_buf += set_tlv_u16(tx_buf, 0x01, sec_key_oid);

	/* Algorithm Identifier */
	tx_buf += set_tlv_u8(tx_buf, 0x05, alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	u8_t *pub_key_len_field = tx_buf;
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

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("CalcSSec Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	const u8_t *out_data = cmds_check_apdu(ctx, &out_len);
	if (out_data == NULL) {
		/* Invalid APDU */
		return -EIO;
	}

	__ASSERT(out_len == 0, "Unexpected data returned");

	return 0;
}

#define OPTIGA_RNG_GEN_EXT_LEN (OPTIGA_TRUSTM_IN_DATA_OFFSET + 2)
int optrust_rng_gen_ext(struct optrust_ctx *ctx, enum OPTRUST_RNG_TYPE type, u8_t *rnd, size_t rnd_len)
{
	__ASSERT(ctx != NULL && rnd != NULL, "No NULL parameters allowed");
	__ASSERT(rnd_len > 0, "Can't generate 0 random bytes");
	if (ctx->apdu_buf_len < OPTIGA_RNG_GEN_EXT_LEN) {
		/* APDU buffer to small */
		return -ENOMEM;
	}

	if (rnd_len > 0x100) {
		/* Requesting too many bytes */
		return -EINVAL;
	}

	/* Skip to APDU inData field */
	u8_t *tx_buf = ctx->apdu_buf + OPTIGA_TRUSTM_IN_DATA_OFFSET;

	u16_t request_len = rnd_len < 8 ? 8 : (u16_t) rnd_len;

	/* Length of random stream */
	sys_put_be16(request_len, tx_buf);
	tx_buf += 2;

	int result_code = cmds_submit_apdu(ctx,
						tx_buf,
						OPTIGA_TRUSTM_CMD_GET_RANDOM,
						(u8_t) type /* Param */);

	if (result_code < 0) {
		/* Our driver errored */
		return result_code;
	} else if (result_code > 0) {
		/* OPTIGA produced an error code */
		LOG_INF("GetRandom Error Code: 0x%02x", result_code);
		return -EIO;
	}

	/* Parse response */

	size_t out_len = 0;
	u8_t *out_data = cmds_check_apdu(ctx, &out_len);
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
