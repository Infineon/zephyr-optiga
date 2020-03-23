/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crypto_optiga.h"

#include "optiga_pre.h"
#include "optiga_nettran.h"

#include <sys/byteorder.h>

#include <mbedtls/md.h>
#include <mbedtls/ccm.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga_pre);

enum OPTIGA_PRE_SCTR_PROTOCOL {
	OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE  = 0x00 << 5,
	OPTIGA_PRE_SCTR_PROTOCOL_REC_EXCHG  = 0x01 << 5,
	OPTIGA_PRE_SCTR_PROTOCOL_ALERT      = 0x02 << 5,
	OPTIGA_PRE_SCTR_PROTOCOL_MANAGE_CTX = 0x01 << 5,
};

/* Handshake messages */
enum OPTIGA_PRE_SCTR_MSG_HS {
	OPTIGA_PRE_SCTR_PROTOCOL_HS_HELLO  = 0x00 << 2,
	OPTIGA_PRE_SCTR_PROTOCOL_HS_KEY_AGREE  = 0x01 << 2,
	OPTIGA_PRE_SCTR_PROTOCOL_HS_FINISHED  = 0x02 << 2,
};

/* Alert messages */
enum OPTIGA_PRE_SCTR_MSG_ALERT {
	OPTIGA_PRE_SCTR_PROTOCOL_ALERT_FATAL  = 0x00 << 2,
	OPTIGA_PRE_SCTR_PROTOCOL_ALERT_INTEGRITY  = 0x01 << 2,
};

/* Manage Context messages */
enum OPTIGA_PRE_SCTR_MSG_CTX {
	OPTIGA_PRE_SCTR_MSG_CTX_SAVE  = 0x00 << 2,
	OPTIGA_PRE_SCTR_MSG_CTX_SAVED  = 0x01 << 2,
	OPTIGA_PRE_SCTR_MSG_CTX_RESTORE  = 0x02 << 2,
	OPTIGA_PRE_SCTR_MSG_CTX_RESTORED  = 0x03 << 2,
};

/* Protection flags */
enum OPTIGA_PRE_SCTR_PROTECTION {
	OPTIGA_PRE_SCTR_PROTECTION_MASTER = 0x01,
	OPTIGA_PRE_SCTR_PROTECTION_SLAVE = 0x02,
};

/* See table 6-3 in IFX I2C Protocol specification */
enum OPTIGA_PRE_PVER {
	OPTIGA_PRE_PVER_PRE_SHARED = 0x01,
	OPTIGA_PRE_PVER_ECDHE = 0x02,
};

#define OPTIGA_PRE_SCTR_OFFS 0
#define OPTIGA_PRE_SCTR_LEN 1

#define OPTIGA_PRE_PVER_OFFS (OPTIGA_PRE_SCTR_OFFS + OPTIGA_PRE_SCTR_LEN)
#define OPTIGA_PRE_PVER_LEN 1

#define OPTIGA_PRE_RND_OFFS (OPTIGA_PRE_PVER_OFFS + OPTIGA_PRE_PVER_LEN)
#define OPTIGA_PRE_RND_LEN 32

#define OPTIGA_PRE_SSEQ_OFFS (OPTIGA_PRE_RND_OFFS + OPTIGA_PRE_RND_LEN)
#define OPTIGA_PRE_SSEQ_LEN 4

#define OPTIGA_PRE_LABEL "Platform Binding"
#define OPTIGA_PRE_DERIVED_LEN 40

#define OPTIGA_PRE_SEQ_LEN 4

/* Split for output of tls_prf_sha256 */
#define OPTIGA_PRE_M_ENC_KEY_OFFS 0
#define OPTIGA_PRE_M_ENC_KEY_LEN OPTIGA_PRE_AES128_KEY_LEN

#define OPTIGA_PRE_M_DEC_KEY_OFFS (OPTIGA_PRE_M_ENC_KEY_OFFS + OPTIGA_PRE_M_ENC_KEY_LEN)
#define OPTIGA_PRE_M_DEC_KEY_LEN OPTIGA_PRE_AES128_KEY_LEN

#define OPTIGA_PRE_M_ENC_NONCE_OFFS (OPTIGA_PRE_M_DEC_KEY_OFFS + OPTIGA_PRE_M_DEC_KEY_LEN)
#define OPTIGA_PRE_M_ENC_NONCE_LEN 4

#define OPTIGA_PRE_M_DEC_NONCE_OFFS (OPTIGA_PRE_M_ENC_NONCE_OFFS + OPTIGA_PRE_M_ENC_NONCE_LEN)
#define OPTIGA_PRE_M_DEC_NONCE_LEN 4

/* Offset of SSEQ/MSEQ in NONCE data */
#define OPTIGA_PRE_NONCE_SEQ_OFFS 4

/* Payload length of "Finish" phase of handshake */
#define OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN (OPTIGA_PRE_RND_LEN + OPTIGA_PRE_SEQ_LEN)


// ported from ssl_tls.c, maybe replace with export from mbedtls?
static int tls_prf_sha256( const u8_t *secret, size_t slen,
                           const char *label,
                           const u8_t *random, size_t rlen,
                           u8_t *dstbuf, size_t dlen )
{
	size_t nb;
	size_t i, j, k, md_len;
	u8_t tmp[128];
	u8_t h_i[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info;
	mbedtls_md_context_t md_ctx;
	int ret;

	mbedtls_md_init( &md_ctx );

	md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );

	if (md_info == NULL) {
		return -EINVAL;
	}

	md_len = mbedtls_md_get_size( md_info );

	if ( sizeof( tmp ) < md_len + strlen( label ) + rlen ) {
		return -EINVAL;
	}

	nb = strlen( label );
	memcpy( tmp + md_len, label, nb );
	memcpy( tmp + md_len + nb, random, rlen );
	nb += rlen;

	/*
	* Compute P_<hash>(secret, label + random)[0..dlen]
	*/

	ret = mbedtls_md_setup( &md_ctx, md_info, 1 );

	if (ret != 0) {
		return -EINVAL;
	}

	mbedtls_md_hmac_starts( &md_ctx, secret, slen );
	mbedtls_md_hmac_update( &md_ctx, tmp + md_len, nb );
	mbedtls_md_hmac_finish( &md_ctx, tmp );

	for( i = 0; i < dlen; i += md_len )
	{
		mbedtls_md_hmac_reset ( &md_ctx );
		mbedtls_md_hmac_update( &md_ctx, tmp, md_len + nb );
		mbedtls_md_hmac_finish( &md_ctx, h_i );

		mbedtls_md_hmac_reset ( &md_ctx );
		mbedtls_md_hmac_update( &md_ctx, tmp, md_len );
		mbedtls_md_hmac_finish( &md_ctx, tmp );

		k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

		for( j = 0; j < k; j++ ) {
			dstbuf[i + j]  = h_i[j];
		}
	}

	mbedtls_md_free( &md_ctx );

	mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
	mbedtls_platform_zeroize( h_i, sizeof( h_i ) );

	return 0;
}

static void optiga_pre_seq_inc(u8_t *seq)
{
	u32_t tmp = sys_get_be32(seq);
	tmp++;
	// TODO(chr): check for overflow?
	sys_put_be32(tmp, seq);
}

int optiga_pre_init(struct device *dev) {
	return 0;
}

/*
 * @brief Sets the shared secrect and derives session keys
 * @param dev Device to operate on
 * @param ssec Pointer to shared secret, NULL invalidates all session data
 * @param ssec_len Length of ssec, 0 invalidates all session data
 */
int optiga_pre_set_shared_secret(struct device *dev, const u8_t *ssec, size_t ssec_len)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;
	if (ssec == NULL || ssec_len == 0) {
		memset(pres->pre_shared_secret, 0, OPTIGA_PRE_PRE_SHARED_SECRET_LEN);
		memset(pres->master_enc_key, 0, OPTIGA_PRE_AES128_KEY_LEN);
		memset(pres->master_dec_key, 0, OPTIGA_PRE_AES128_KEY_LEN);
		memset(pres->master_enc_nonce, 0, OPTIGA_PRE_AES128_NONCE_LEN);
		memset(pres->master_dec_nonce, 0, OPTIGA_PRE_AES128_NONCE_LEN);
		memset(pres->encrypted_apdu, 0, OPTIGA_PRE_MAX_ENC_APDU_LEN);
	} else {
		if (ssec_len != OPTIGA_PRE_PRE_SHARED_SECRET_LEN) {
			/* Invalid shared secret */
			return -EINVAL;
		}

		memcpy(pres->pre_shared_secret, ssec, ssec_len);
	}

	return 0;
}

static size_t optiga_pre_send_hello(u8_t *buf)
{
	buf[OPTIGA_PRE_SCTR_OFFS] = OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE | OPTIGA_PRE_SCTR_PROTOCOL_HS_HELLO;
	/* Only support pre shared key for now */
	buf[OPTIGA_PRE_PVER_OFFS] = OPTIGA_PRE_PVER_PRE_SHARED;

	return OPTIGA_PRE_PVER_OFFS + OPTIGA_PRE_PVER_LEN;
}

static int optiga_pre_recv_hello(struct device *dev, u8_t *buf, size_t len, const u8_t **rnd)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	if (len != (OPTIGA_PRE_SSEQ_OFFS + OPTIGA_PRE_SSEQ_LEN)) {
		/* Unexpected length */
		return -EINVAL;
	}

	if (buf[OPTIGA_PRE_SCTR_OFFS] != (OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE | OPTIGA_PRE_SCTR_PROTOCOL_HS_HELLO)) {
		/* Unexpected message */
		return -EINVAL;
	}

	if (buf[OPTIGA_PRE_PVER_OFFS] != OPTIGA_PRE_PVER_PRE_SHARED) {
		/* Unsupported handshake type */
		return -EINVAL;
	}

	*rnd = &buf[OPTIGA_PRE_RND_OFFS];

	/* Put SSEQ into master encryption nonce */
	memcpy(&pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], &buf[OPTIGA_PRE_SSEQ_OFFS], OPTIGA_PRE_SSEQ_LEN);

	return 0;
}

static int optiga_pre_derive_keys(struct device *dev, const u8_t *rnd)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	u8_t tmp_buf[OPTIGA_PRE_DERIVED_LEN] = {0};

	int res = tls_prf_sha256(pres->pre_shared_secret, OPTIGA_PRE_PRE_SHARED_SECRET_LEN,
			OPTIGA_PRE_LABEL,
			rnd, OPTIGA_PRE_RND_LEN,
			tmp_buf, OPTIGA_PRE_DERIVED_LEN);
	if (res != 0) {
		return res;
	}

	memcpy(pres->master_enc_key, &tmp_buf[OPTIGA_PRE_M_ENC_KEY_OFFS], OPTIGA_PRE_M_ENC_KEY_LEN);
	memcpy(pres->master_dec_key, &tmp_buf[OPTIGA_PRE_M_DEC_KEY_OFFS], OPTIGA_PRE_M_DEC_KEY_LEN);

	memcpy(pres->master_enc_nonce, &tmp_buf[OPTIGA_PRE_M_ENC_NONCE_OFFS], OPTIGA_PRE_M_ENC_NONCE_LEN);
	memcpy(pres->master_dec_nonce, &tmp_buf[OPTIGA_PRE_M_DEC_NONCE_OFFS], OPTIGA_PRE_M_DEC_NONCE_LEN);

	return 0;
}

void optiga_pre_assemble_assoc_data(struct device *dev, u8_t sctr, const u8_t *seq, u8_t pver, u16_t payload_len)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;
	u8_t *assoc = pres->assoc_data_buf;

	*assoc = sctr;
	assoc += OPTIGA_PRE_SCTR_LEN;

	memcpy(assoc, seq, OPTIGA_PRE_SEQ_LEN);
	assoc += OPTIGA_PRE_SEQ_LEN;

	*assoc = pver;
	assoc += OPTIGA_PRE_PVER_LEN;

	sys_put_be16(payload_len, assoc);
}

int optiga_pre_send_handshake_finished(struct device *dev, const u8_t *rnd)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	const u8_t *sseq = &pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];

	mbedtls_ccm_init(&pres->aes_ccm_ctx);

	int res = mbedtls_ccm_setkey(&pres->aes_ccm_ctx,
					MBEDTLS_CIPHER_ID_AES,
					pres->master_enc_key,
					OPTIGA_PRE_AES128_KEY_LEN*8);
	if (res != 0) {
		mbedtls_ccm_free(&pres->aes_ccm_ctx);
		return -EINVAL;
	}

	u8_t sctr = OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE | OPTIGA_PRE_SCTR_PROTOCOL_HS_FINISHED;
	u8_t pver = OPTIGA_PRE_PVER_PRE_SHARED;

	/* Assemble associated data */
	optiga_pre_assemble_assoc_data(dev, sctr, sseq, pver, OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN);

	/* Assemble handshake payload */
	u8_t payload[OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN] = {0};
	memcpy(payload, rnd, OPTIGA_PRE_RND_LEN);
	memcpy(payload + OPTIGA_PRE_RND_LEN, sseq, OPTIGA_PRE_SEQ_LEN);

	/* Assemble final packet header*/
	// TODO(chr): overflow check
	u8_t *packet = pres->encrypted_apdu;

	*packet = sctr;
	packet += OPTIGA_PRE_SCTR_LEN;

	memcpy(packet, sseq, OPTIGA_PRE_SEQ_LEN);
	packet += OPTIGA_PRE_SEQ_LEN;

	/* encrypt payload */
	res = mbedtls_ccm_encrypt_and_tag(&pres->aes_ccm_ctx, 36,
					pres->master_enc_nonce, OPTIGA_PRE_AES128_NONCE_LEN,
					pres->assoc_data_buf, OPTIGA_PRE_ASSOC_DATA_LEN,
					payload,
					packet,
					packet + 36, OPTIGA_PRE_MAC_LEN);

	if(res != 0) {
		mbedtls_ccm_free(&pres->aes_ccm_ctx);
		return -EINVAL;
	}

	packet += 36 + OPTIGA_PRE_MAC_LEN;
	pres->encrypted_apdu_len = packet - pres->encrypted_apdu;
	mbedtls_ccm_free(&pres->aes_ccm_ctx);

	return 0;
}

int optiga_pre_recv_handshake_finished(struct device *dev, u8_t *buf, size_t len)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	if (len != (OPTIGA_PRE_SCTR_LEN + OPTIGA_PRE_SEQ_LEN + OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN + OPTIGA_PRE_MAC_LEN)) {
		/* Unexpected length */
		return -EINVAL;
	}

	const u8_t *packet = buf;

	u8_t sctr = *packet;
	packet += OPTIGA_PRE_SCTR_LEN;
	const u8_t *mseq = packet;
	packet += OPTIGA_PRE_SEQ_LEN;
	u8_t pver = OPTIGA_PRE_PVER_PRE_SHARED;

	/* Assemble associated data */
	optiga_pre_assemble_assoc_data(dev, sctr, mseq, pver, OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN);

	/* Put MSEQ into master decryption nonce */
	memcpy(&pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], mseq, OPTIGA_PRE_SEQ_LEN);

	mbedtls_ccm_init(&pres->aes_ccm_ctx);
	// TODO(chr): extract constant
	int res = mbedtls_ccm_setkey(&pres->aes_ccm_ctx, MBEDTLS_CIPHER_ID_AES,
					pres->master_dec_key,
					OPTIGA_PRE_AES128_KEY_LEN*8);
	if (res != 0) {
		mbedtls_ccm_free(&pres->aes_ccm_ctx);
		return -EINVAL;
	}

	res = mbedtls_ccm_auth_decrypt(&pres->aes_ccm_ctx, OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN,
						pres->master_dec_nonce, OPTIGA_PRE_AES128_NONCE_LEN,
						pres->assoc_data_buf, OPTIGA_PRE_ASSOC_DATA_LEN,
						packet,
						pres->encrypted_apdu,
						packet + OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN, OPTIGA_PRE_MAC_LEN);
	if (res != 0) {
		/* decryption/authentication failure */
		mbedtls_ccm_free(&pres->aes_ccm_ctx);
		return -EINVAL;
	}

	mbedtls_ccm_free(&pres->aes_ccm_ctx);
	return 0;
}
// TODO(chr): implement handshake sequence
int optiga_pre_do_handshake(struct device *dev)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;
#define TMP_BUF_LEN 49
	/* Maximum message length is 49 */
	u8_t tmp_buf[TMP_BUF_LEN] = {0};
	size_t tmp_buf_len = TMP_BUF_LEN;

	/* Enable Presentation layer in NETTRAN */
	optiga_nettran_presence_enable(dev);

	/* First step: request RND and SSEQ */
	tmp_buf_len = optiga_pre_send_hello(tmp_buf);

	int res = optiga_nettran_send_apdu(dev, tmp_buf, tmp_buf_len);
	if (res != 0) {
		return res;
	}

	tmp_buf_len = TMP_BUF_LEN;
	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		return res;
	}

	/* Receive RND and SSEQ */
	const u8_t* rnd = NULL;
	res = optiga_pre_recv_hello(dev, tmp_buf, tmp_buf_len, &rnd);
	if (res != 0) {
		return res;
	}

	/* Derive master and slave encrypt/decrypt keys */
	res = optiga_pre_derive_keys(dev, rnd);
	if (res != 0) {
		return res;
	}

	/* Prepare final handshake message */
	res = optiga_pre_send_handshake_finished(dev, rnd);
	if (res != 0) {
		return res;
	}

	/* send to OPTIGA */
	res = optiga_nettran_send_apdu(dev, pres->encrypted_apdu, pres->encrypted_apdu_len);
	if (res != 0) {
		return res;
	}

	/* Receive final handshake message from OPTIGA */
	tmp_buf_len = TMP_BUF_LEN;
	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		return res;
	}

	res = optiga_pre_recv_handshake_finished(dev, tmp_buf, tmp_buf_len);
	if (res != 0) {
		return res;
	}

	LOG_HEXDUMP_INF(tmp_buf, tmp_buf_len, "Last Handshake msg");

	return 0;
#undef TMP_BUF_LEN
}

int optiga_pre_recv_apdu(struct device *dev, u8_t *data, size_t *len)
{
	if (optiga_nettran_presence_get(dev)) {
		// TODO(chr): implement
		return -ENOTSUP;
	} else {
		return optiga_nettran_recv_apdu(dev, data, len);
	}
}

int optiga_pre_send_apdu(struct device *dev, const u8_t *data, size_t len)
{
	if (optiga_nettran_presence_get(dev)) {
		// TODO(chr): implement
		return -ENOTSUP;
	} else {
		return optiga_nettran_send_apdu(dev, data, len);
	}
}
