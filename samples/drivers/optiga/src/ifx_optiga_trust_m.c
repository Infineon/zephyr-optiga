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
/* Tag + Length + Unused bits + Compressed point marker */
#define DER_BITSTRING_PK_OVERHEAD 4

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
	if (pub_key_len > 125) {
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

static size_t cmds_get_apdu_header(u8_t *apdu_start, u8_t *sta, u16_t *out_len)
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

static int cmds_submit_apdu(struct optrust_ctx *ctx)
{
	optiga_enqueue_apdu(ctx->dev, &ctx->apdu);

	struct k_poll_event events[1] = {
        K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL,
                                 K_POLL_MODE_NOTIFY_ONLY,
                                 &ctx->apdu.finished),
	};

	k_poll(events, 1, K_FOREVER);
	return events[0].signal->result;
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



#define OPTIGA_GET_DATA_CMD_LEN 10
int optrust_data_get(struct optrust_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len)
{
	__ASSERT(ctx != NULL && buf != NULL && len != NULL, "No NULL parameters allowed");
	__ASSERT(ctx->apdu_buf_len >= OPTIGA_GET_DATA_CMD_LEN, "APDU buffer too small");

	if (offs > U16_MAX || *len > U16_MAX) {
		/* Prevent overflow in parameter encoding */
		return -EINVAL;
	}

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTM_CMD_GET_DATA_OBJECT,
				0x00, /* Read data */
				0x06 /* Command len, see datasheet Table 8 */);

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

	int result_code = cmds_submit_apdu(ctx);

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
	rx_buf += cmds_get_apdu_header(rx_buf, &sta, &out_len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	/* Ensure length of APDU and length of buffer match */
	if (out_len != (ctx->apdu.rx_len - OPTIGA_TRUSTM_OUT_DATA_OFFSET)) {
		LOG_ERR("Incomplete APDU");
		return -EIO;
	}

	if(out_len > *len) {
		return -ENOMEM;
	}

	memcpy(buf, rx_buf, out_len);
	*len = out_len;
	return 0;
}

int optrust_data_set(struct optrust_ctx *ctx, u16_t oid, bool erase, size_t offs, const u8_t *buf, size_t len)
{
	__ASSERT(ctx != NULL && buf != NULL, "No NULL parameters allowed");
	__ASSERT(ctx->apdu_buf_len >= (len + 8), "APDU buffer too small");

	if(len + 4 > OPTIGA_TRUSTM_IN_LEN_MAX) {
		LOG_ERR("Overflow in APDU header");
		return -EINVAL;
	}

	if (offs > U16_MAX) {
		/* Prevent overflow in parameter encoding */
		return -EINVAL;
	}

	const u8_t param = erase ? OPTIGA_TRUSTM_SET_DATA_OBJECT_ERASE_WRITE_DATA
		: OPTIGA_TRUSTM_SET_DATA_OBJECT_WRITE_DATA;

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTM_CMD_SET_DATA_OBJECT,
				param, /* Param */
				len + 4 /* Length of the Tx APDU */
			);

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

	int result_code = cmds_submit_apdu(ctx);

	if(result_code != OPTIGA_STATUS_CODE_SUCCESS) {
		LOG_INF("SetDataObject Error Code: %d", result_code);
		return -EIO;
	}

	return 0;
}

int optrust_ecdsa_sign_oid(struct optrust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");
	__ASSERT(ctx->apdu_buf_len >= (digest_len + 12), "APDU buffer too small");
	if(digest_len + 8 > OPTIGA_TRUSTM_IN_LEN_MAX) {
		LOG_ERR("Overflow in APDU header");
		return -EINVAL;
	}

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTM_CMD_CALC_SIGN,
				0x11, /* ECDSA FIPS 186-3 w/o hash */
				digest_len + 8 /* Length of the Tx APDU */
			);

	/* Digest to be signed */
	tx_buf += set_tlv(tx_buf, 0x01, digest, digest_len);

	/* OID of signature key */
	tx_buf += set_tlv_u16(tx_buf, 0x03, oid);

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	int result_code = cmds_submit_apdu(ctx);

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
	rx_buf += cmds_get_apdu_header(rx_buf, &sta, &out_len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	/* Ensure length of APDU and length of buffer match */
	if (out_len != (ctx->apdu.rx_len - OPTIGA_TRUSTM_OUT_DATA_OFFSET)) {
		LOG_ERR("Incomplete APDU");
		return -EIO;
	}

	/* decode to raw RS values */
	bool success = asn1_to_ecdsa_rs(rx_buf, out_len, signature, signature_len);
	if(!success) {
		LOG_ERR("Failed to decode signature");
		return -EIO;
	}

	return 0;
}

int optrust_ecdsa_verify_ext(struct optrust_ctx *ctx, enum OPTRUST_ALGORITHM alg,
				const u8_t *pub_key, size_t pub_key_len,
				const u8_t *digest, size_t digest_len,
				const u8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");
	// TODO(chr): adapt length check
	__ASSERT(ctx->apdu_buf_len >= (digest_len + 15), "APDU buffer too small");

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

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += OPTIGA_TRUSTM_IN_DATA_OFFSET;
	const u8_t *tx_buf_in_data = tx_buf;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, digest_len);

	/* Second parameter */
	*tx_buf = 0x02;
	tx_buf++;

	/* we don't know the length of the signature data and public key yet, remember the position */
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

	if(digest_len + 11 + asn1_sig_len > OPTIGA_TRUSTM_IN_LEN_MAX) {
		LOG_ERR("Overflow in APDU header");
		return -EINVAL;
	}

	/* length of signature is known now */
	sys_put_be16(asn1_sig_len, sig_len_field);

	/* Algorithm identifier of public key */
	tx_buf += set_tlv_u8(tx_buf, 0x05, alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	u8_t *pub_key_len_field = tx_buf;
	tx_buf += 2;

	/* Public key Value */
	size_t remaining_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf);
	size_t pub_key_asn1_len = set_pub_key_as_bitstring(tx_buf, remaining_len, pub_key, pub_key_len);
	if (pub_key_asn1_len == 0) {
		/* Encoding error */
		return -EINVAL;
	}

	tx_buf += pub_key_asn1_len;

	/* Public key length know now */
	sys_put_be16(pub_key_asn1_len, pub_key_len_field);

	/* length of whole apdu is also known now */
	cmds_set_apdu_header(ctx->apdu_buf,
				OPTIGA_TRUSTM_CMD_VERIFY_SIGN,
				0x11, /* ECDSA FIPS 186-3 w/o hash */
				tx_buf - tx_buf_in_data /* Length of the Tx APDU */
			);

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	int result_code = cmds_submit_apdu(ctx);

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

int optrust_ecdsa_verify_oid(struct optrust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, const u8_t *signature, size_t signature_len)
{
	__ASSERT(ctx != NULL && digest != NULL && signature != NULL, "No NULL parameters allowed");
	__ASSERT(ctx->apdu_buf_len >= (digest_len + 15), "APDU buffer too small");

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* Digest */
	tx_buf += set_tlv(tx_buf, 0x01, digest, digest_len);

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

	if(digest_len + 11 + asn1_sig_len > OPTIGA_TRUSTM_IN_LEN_MAX) {
		LOG_ERR("Overflow in APDU header");
		return -EINVAL;
	}

	/* length of signature is known now */
	sys_put_be16(asn1_sig_len, sig_len_field);

	/* length of whole apdu is also known now */
	cmds_set_apdu_header(ctx->apdu_buf,
				OPTIGA_TRUSTM_CMD_VERIFY_SIGN,
				0x11, /* ECDSA FIPS 186-3 w/o hash */
				digest_len + 11 + asn1_sig_len /* Length of the Tx APDU */
			);

	/* OID of Public Key Certificate */
	tx_buf += set_tlv_u16(tx_buf, 0x04, oid);

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	int result_code = cmds_submit_apdu(ctx);

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

int optrust_ecc_gen_keys_oid(struct optrust_ctx *ctx, u16_t oid, enum OPTRUST_ALGORITHM alg,
                enum OPTRUST_KEY_USAGE_FLAG key_usage, u8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL, "No NULL parameters allowed");
	__ASSERT(ctx->apdu_buf_len >= 11, "APDU buffer too small");

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

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTM_CMD_GEN_KEYPAIR,
				alg, /* Key algorithm */
				0x09 /* Command len, see datasheet Table 19 */);

	/* OID */
	tx_buf += set_tlv_u16(tx_buf, 0x01, oid);

	/* Key usage identifier */
	tx_buf += set_tlv_u8(tx_buf, 0x02, key_usage);

	/*
	 * Setup APDU for cmd queue, reuse the tx_buf for receiving,
	 * we don't need the written data
	 */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = ctx->apdu_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len;

	int result_code = cmds_submit_apdu(ctx);

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
	rx_buf += cmds_get_apdu_header(rx_buf, &sta, &out_len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	/* Ensure length of APDU and length of buffer match */
	if (out_len != (ctx->apdu.rx_len - OPTIGA_TRUSTM_OUT_DATA_OFFSET)) {
		LOG_ERR("Incomplete APDU");
		return -EIO;
	}

	__ASSERT(rx_buf[0] == 0x02, "Received Key not a pub key");

	// TODO(chr): decide if we can skip ASN.1 decoding
	/* the following decoding routine only works if the public key has a fixed length */
	__ASSERT(out_len == (*pub_key_len + 7), "Assumption about pub key encoding was wrong");
	rx_buf += 3; // skip tag and length
	rx_buf += 4; // skip ASN.1 tag, length and 2 value bytes
	memcpy(pub_key, rx_buf, *pub_key_len);

	return 0;
}

int optrust_ecc_gen_keys_ext(struct optrust_ctx *ctx,
				enum OPTRUST_ALGORITHM alg,
				u8_t *sec_key, size_t *sec_key_len,
				u8_t *pub_key, size_t *pub_key_len)
{
	__ASSERT(ctx != NULL && pub_key != NULL && pub_key_len != NULL
		&& sec_key != NULL && sec_key_len != NULL, "No NULL parameters allowed");
	// TODO(chr): compute needed buffer size
	__ASSERT(ctx->apdu_buf_len >= 200, "APDU buffer too small");

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

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTM_CMD_GEN_KEYPAIR,
				alg, /* Key algorithm */
				0x03 /* Command len, see datasheet Table 19 */);

	/* Export key pair in plain */
	tx_buf += set_tlv(tx_buf, 0x07, NULL, 0);

	/*
	 * Setup APDU for cmd queue, reuse the tx_buf for receiving,
	 * we don't need the written data
	 */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = ctx->apdu_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len;

	int result_code = cmds_submit_apdu(ctx);

	if(result_code != OPTIGA_STATUS_CODE_SUCCESS) {
		LOG_INF("GetDataObject Error Code: %d", result_code);
		return -EIO;
	}

	/* Parse response */

	/* need at least the 4 bytes of response data */
	__ASSERT(ctx->apdu.rx_len >= 4, "Malformed APDU");

	u8_t *rx_buf = ctx->apdu.rx_buf;
	size_t rx_len = ctx->apdu.rx_len;

	u8_t sta = 0;
	u16_t out_len = 0;
	rx_buf += cmds_get_apdu_header(rx_buf, &sta, &out_len);

	LOG_HEXDUMP_INF(rx_buf, out_len, "RX APDU");

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	__ASSERT(((OPTIGA_TRUSTM_IN_DATA_OFFSET + out_len) == rx_len), "Invalid length in APDU");
	// TODO(chr): more robust ASN.1 decoding

	u8_t tag = 0;
	u16_t len = 0;
	u8_t *sec_key_asn1 = NULL;

	/* Parse secrect key */
	bool res = get_tlv(rx_buf, out_len, &tag, &len, &sec_key_asn1);
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

	__ASSERT(sec_key_asn1[0] == 0x04, "Not an DER OCTECT STRING");
	__ASSERT(sec_key_asn1[1] == *sec_key_len, "Length mismatch");

	sec_key_asn1 += 2;
	memcpy(sec_key, sec_key_asn1, *sec_key_len);

	/* Parse public key */
	rx_buf = sec_key_asn1 + *sec_key_len;
	out_len -= len;

	u8_t *pub_key_asn1 = NULL;
	res = get_tlv(rx_buf, rx_len, &tag, &len, &pub_key_asn1);
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

int optrust_sha256_oid(struct optrust_ctx *ctx,
				u16_t oid, size_t offs, size_t len,
				u8_t *digest, size_t *digest_len)
{
	__ASSERT(ctx != NULL && digest != NULL && digest_len != NULL, "No NULL parameters allowed");
	__ASSERT(ctx->apdu_buf_len >= (OPTIGA_TRUSTM_IN_DATA_OFFSET + 9), "APDU buffer too small");

	if (offs > UINT16_MAX || len > UINT16_MAX) {
		/* Overflow in Offset and Length field */
		return -EINVAL;
	}

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTM_CMD_CALC_HASH,
                OPTRUST_ALGORITHM_SHA256, /* Param */
				9 /* Length of the Tx APDU */
			);

	/* Tag */
	*tx_buf = OPTIGA_TRUSTM_CALC_HASH_OID_START_FINAL;
	tx_buf += 1;

	/* Length */
	sys_put_be16(0x06, tx_buf);
	tx_buf += 2;

	/* OID */
	sys_put_be16(oid, tx_buf);
	tx_buf += 2;

	/* Offset */
	sys_put_be16(offs, tx_buf);
	tx_buf += 2;

	/* Length */
	sys_put_be16(len, tx_buf);
	tx_buf += 2;

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	int result_code = cmds_submit_apdu(ctx);

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
	rx_buf += cmds_get_apdu_header(rx_buf, &sta, &out_len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");
	__ASSERT(out_len == (OPTRUST_SHA256_DIGEST_LEN + 3), "Unexpected data returned");

	/* Skip Tag + Length */
	rx_buf += 3;
	out_len -= 3;

	if (*digest_len < out_len) {
		return -ENOMEM;
	}

	memcpy(digest, rx_buf, out_len);

	return 0;
}

int optrust_ecdh_calc_oid(struct optrust_ctx *ctx, u16_t sec_key_oid,
				enum OPTRUST_ALGORITHM alg,
				const u8_t *pub_key, size_t pub_key_len,
				u16_t shared_secret_oid)
{
	__ASSERT(ctx != NULL && pub_key != NULL, "No NULL parameters allowed");

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

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += OPTIGA_TRUSTM_IN_DATA_OFFSET;

	/* OID of Private Key */
	tx_buf += set_tlv_u16(tx_buf, 0x01, sec_key_oid);

	// TODO(chr): code duplication with optrust_ecdsa_verify_ext
	/* Algorithm Identifier */
	tx_buf += set_tlv_u8(tx_buf, 0x05, alg);

	/* Public key Tag */
	*tx_buf = 0x06;
	tx_buf++;

	/* Public key Length, not known yet */
	u8_t *pub_key_len_field = tx_buf;
	tx_buf += 2;

	/* Public key Value */
	size_t remaining_len = ctx->apdu_buf_len - (tx_buf - ctx->apdu_buf);
	size_t pub_key_asn1_len = set_pub_key_as_bitstring(tx_buf, remaining_len, pub_key, pub_key_len);
	if (pub_key_asn1_len == 0) {
		/* Encoding error */
		return -EINVAL;
	}
	tx_buf += pub_key_asn1_len;

	/* Public key length know now */
	sys_put_be16(pub_key_asn1_len, pub_key_len_field);

	/* OID of Shared Secret */
	tx_buf += set_tlv_u16(tx_buf, 0x08, shared_secret_oid);

	cmds_set_apdu_header(ctx->apdu_buf,
				OPTIGA_TRUSTM_CMD_CALC_SSEC,
				OPTIGA_TRUSTM_KEY_AGREEMENT_ECDH, /* Param */
				tx_buf - ctx->apdu_buf -  OPTIGA_TRUSTM_IN_DATA_OFFSET/* Length of the Tx APDU */
				);

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	int result_code = cmds_submit_apdu(ctx);

	if(result_code != OPTIGA_STATUS_CODE_SUCCESS) {
		LOG_INF("DeriveSSec Error Code: %d", result_code);
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

int optrust_rng_gen_ext(struct optrust_ctx *ctx, enum OPTRUST_RNG_TYPE type, u8_t *rnd, size_t rnd_len)
{
	__ASSERT(ctx != NULL && rnd != NULL, "No NULL parameters allowed");
	__ASSERT(rnd_len > 0, "Can't generate 0 random bytes");

	if (rnd_len > 0x100) {
		/* Requesting too many bytes */
		return -EINVAL;
	}

	u8_t *tx_buf = ctx->apdu_buf;
	tx_buf += cmds_set_apdu_header(tx_buf,
				OPTIGA_TRUSTM_CMD_GET_RANDOM,
				(u8_t) type, /* Param */
				2 /* Length of the Tx APDU */
				);
	u16_t request_len = rnd_len < 8 ? 8 : (u16_t) rnd_len;
	/* Length of random stream */
	sys_put_be16(request_len, tx_buf);
	tx_buf += 2;

	/* Setup APDU for cmd queue */
	ctx->apdu.tx_buf = ctx->apdu_buf;
	ctx->apdu.tx_len = tx_buf - ctx->apdu_buf;
	ctx->apdu.rx_buf = tx_buf;
	ctx->apdu.rx_len = ctx->apdu_buf_len - ctx->apdu.tx_len;

	int result_code = cmds_submit_apdu(ctx);

	if(result_code != OPTIGA_STATUS_CODE_SUCCESS) {
		LOG_INF("GetRandom Error Code: %d", result_code);
		return -EIO;
	}

	/* Parse response */

	/* need at least the 4 bytes of response data */
	__ASSERT(ctx->apdu.rx_len >= 4, "Malformed APDU");

	u8_t *rx_buf = ctx->apdu.rx_buf;

	u8_t sta = 0;
	u16_t out_len = 0;
	rx_buf += cmds_get_apdu_header(rx_buf, &sta, &out_len);

	/* Failed APDUs should never reach this layer */
	__ASSERT(sta == 0x00, "Unexpected failed APDU");

	if (out_len != request_len) {
		/* Unexpected amount of data */
		return -EIO;
	}

	memcpy(rnd, rx_buf, rnd_len);
	return 0;
}
