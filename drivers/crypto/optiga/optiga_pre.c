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
	OPTIGA_PRE_SCTR_PROTOCOL_MANAGE_CTX = 0x03 << 5,
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

#define OPTIGA_PRE_PVER_OFFS (OPTIGA_PRE_SCTR_OFFS + OPTIGA_PRE_SCTR_LEN)
#define OPTIGA_PRE_PVER_LEN 1

#define OPTIGA_PRE_RND_OFFS (OPTIGA_PRE_PVER_OFFS + OPTIGA_PRE_PVER_LEN)

#define OPTIGA_PRE_SSEQ_OFFS (OPTIGA_PRE_RND_OFFS + OPTIGA_PRE_RND_LEN)

#define OPTIGA_PRE_LABEL "Platform Binding"
#define OPTIGA_PRE_LABEL_STRLEN 16
#define OPTIGA_PRE_SHA256_LEN 32

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

/* Payload length of "Hello" message from Master to Slave */
#define OPTIGA_PRE_HS_HOST_HELLO (OPTIGA_PRE_SCTR_LEN + OPTIGA_PRE_PVER_LEN)

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
	// TODO(chr): move these buffers to handshake scratch space
	u8_t tmp[OPTIGA_PRE_LABEL_STRLEN + OPTIGA_PRE_SHA256_LEN + OPTIGA_PRE_RND_LEN];
	u8_t h_i[OPTIGA_PRE_SHA256_LEN];
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

/*
 * @brief Check if SEQ has reached the maximum value
 * @param seq SEQ value to check
 * @return true when the maximum is reached, false else
 */
static bool optiga_pre_seq_max(const u8_t *seq)
{
	u32_t tmp = sys_get_be32(seq);
	return tmp == UINT32_MAX;
}

/*
 * @brief Increment SEQ value
 * @param seq SEQ value to increment
 * @return true when SEQ was incremented, false on overflow
 * @note The return value of this function MUST be checked, if it's false
 *       SEQ must not be used for encryption.
 */
static bool optiga_pre_seq_inc(u8_t *seq)
{
	if (optiga_pre_seq_max(seq)) {
		return false;
	}

	u32_t tmp = sys_get_be32(seq);
	tmp++;
	sys_put_be32(tmp, seq);
	return true;
}

/* For debugging purposes */
void optiga_pre_seq_get(struct device *dev, u32_t *mseq, u32_t *sseq)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	const u8_t *mseq_l = &pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];
	const u8_t *sseq_l = &pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];

	*mseq = sys_get_be32(mseq_l);
	*sseq = sys_get_be32(sseq_l);
}

void optiga_pre_clear_keys(struct present_layer *pres)
{
	mbedtls_platform_zeroize(pres->master_enc_key, OPTIGA_PRE_AES128_KEY_LEN);
	mbedtls_platform_zeroize(pres->master_dec_key, OPTIGA_PRE_AES128_KEY_LEN);
	mbedtls_platform_zeroize(pres->master_enc_nonce, OPTIGA_PRE_AES128_NONCE_LEN);
	mbedtls_platform_zeroize(pres->master_dec_nonce, OPTIGA_PRE_AES128_NONCE_LEN);
	mbedtls_platform_zeroize(&pres->buf, sizeof(pres->buf));
}

int optiga_pre_init(struct device *dev) {
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	optiga_pre_clear_keys(pres);
	return 0;
}

/*
 * @brief Sets the shared secrect
 * @param dev Device to operate on
 * @param ssec Pointer to shared secret, NULL invalidates all session data
 * @param ssec_len Length of ssec, 0 invalidates all session data
 */
int optiga_pre_set_shared_secret(struct device *dev, const u8_t *ssec, size_t ssec_len)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;
	if (ssec == NULL || ssec_len == 0) {
		optiga_pre_clear_keys(pres);
	} else {
		if (ssec_len != OPTIGA_PRE_PRE_SHARED_SECRET_LEN) {
			/* Invalid shared secret */
			return -EINVAL;
		}

		memcpy(pres->pre_shared_secret, ssec, ssec_len);
	}

	return 0;
}

/**
 * @brief Prepare the "Hello" message from Master to Slave
 *
 * Prepares the "Hello" message from Master to Slave in the scratch buffer.
 */
static void optiga_pre_assemble_hello(struct present_layer *pres)
{
	/* Use handshake buffer */
	struct optiga_pre_handshake_buf *hs_buf = &pres->buf.hs;

	hs_buf->scratch[OPTIGA_PRE_SCTR_OFFS] = OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE | OPTIGA_PRE_SCTR_PROTOCOL_HS_HELLO;
	hs_buf->scratch[OPTIGA_PRE_PVER_OFFS] = pres->pver;
	hs_buf->scratch_len = OPTIGA_PRE_HS_HOST_HELLO;
}

/**
 * @brief Parse the "Hello" message from Slave to Master
 * @param pres Presentation layer instance to work on
 *
 * Parse the "Hello" message from Slave to Master stored in scratch memory.
 */
static int optiga_pre_parse_hello(struct present_layer *pres)
{
	/* Use handshake buffer */
	struct optiga_pre_handshake_buf *hs_buf = &pres->buf.hs;
	const u8_t *packet = hs_buf->scratch;
	const size_t packet_len = hs_buf->scratch_len;

	if (packet_len != (OPTIGA_PRE_SSEQ_OFFS + OPTIGA_PRE_SEQ_LEN)) {
		/* Unexpected length */
		return -EINVAL;
	}

	if (packet[OPTIGA_PRE_SCTR_OFFS] != (OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE | OPTIGA_PRE_SCTR_PROTOCOL_HS_HELLO)) {
		/* Unexpected message */
		return -EINVAL;
	}

	if (packet[OPTIGA_PRE_PVER_OFFS] != pres->pver) {
		/* Unsupported handshake type */
		return -EINVAL;
	}

	/* Keep RND value */
	memcpy(hs_buf->rnd, &packet[OPTIGA_PRE_RND_OFFS], OPTIGA_PRE_RND_LEN);

	/* Put SSEQ into master encryption nonce */
	memcpy(&pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], &packet[OPTIGA_PRE_SSEQ_OFFS], OPTIGA_PRE_SEQ_LEN);

	return 0;
}

static int optiga_pre_derive_keys(struct present_layer *pres)
{
	/* Use handshake buffer */
	struct optiga_pre_handshake_buf *hs_buf = &pres->buf.hs;

	int res = tls_prf_sha256(pres->pre_shared_secret, OPTIGA_PRE_PRE_SHARED_SECRET_LEN,
			OPTIGA_PRE_LABEL,
			hs_buf->rnd, OPTIGA_PRE_RND_LEN,
			hs_buf->deriv_secret, OPTIGA_PRE_DERIVED_SECRET_LEN);
	if (res != 0) {
		return res;
	}

	memcpy(pres->master_enc_key, &hs_buf->deriv_secret[OPTIGA_PRE_M_ENC_KEY_OFFS], OPTIGA_PRE_M_ENC_KEY_LEN);
	memcpy(pres->master_dec_key, &hs_buf->deriv_secret[OPTIGA_PRE_M_DEC_KEY_OFFS], OPTIGA_PRE_M_DEC_KEY_LEN);

	memcpy(pres->master_enc_nonce, &hs_buf->deriv_secret[OPTIGA_PRE_M_ENC_NONCE_OFFS], OPTIGA_PRE_M_ENC_NONCE_LEN);
	memcpy(pres->master_dec_nonce, &hs_buf->deriv_secret[OPTIGA_PRE_M_DEC_NONCE_OFFS], OPTIGA_PRE_M_DEC_NONCE_LEN);

	return 0;
}

/**
 * @brief Helper to assemble the associated data for encryption/decryption
 * @param pres Presentation layer instance
 * @param sctr SCTR value of associated data
 * @param seq Pointer to SEQ field of associated data
 * @param payload_len Length of the payload
 */
static void optiga_pre_assemble_assoc_data(struct present_layer *pres, u8_t sctr, const u8_t *seq, u16_t payload_len)
{
	u8_t *assoc = pres->assoc_data_buf;

	*assoc = sctr;
	assoc += OPTIGA_PRE_SCTR_LEN;

	memcpy(assoc, seq, OPTIGA_PRE_SEQ_LEN);
	assoc += OPTIGA_PRE_SEQ_LEN;

	*assoc = pres->pver;
	assoc += OPTIGA_PRE_PVER_LEN;

	sys_put_be16(payload_len, assoc);
}

int optiga_pre_encrypt(struct present_layer *pres, u8_t sctr, const u8_t *seq, const u8_t *payload, size_t payload_len, u8_t *out_buf, size_t *out_len)
{
	if (payload_len > *out_len) {
		/* Buffer too small */
		return -ENOMEM;
	}

	/* Assemble associated data */
	optiga_pre_assemble_assoc_data(pres, sctr, seq, payload_len);

	/* Assemble final packet header*/
	u8_t *packet = out_buf;

	/* SCTR field */
	*packet = sctr;
	packet += OPTIGA_PRE_SCTR_LEN;

	/* SEQ field */
	memcpy(packet, seq, OPTIGA_PRE_SEQ_LEN);
	packet += OPTIGA_PRE_SEQ_LEN;

	mbedtls_ccm_init(&pres->aes_ccm_ctx);

	int res = mbedtls_ccm_setkey(&pres->aes_ccm_ctx,
					MBEDTLS_CIPHER_ID_AES,
					pres->master_enc_key,
					OPTIGA_PRE_AES128_KEY_LEN*8);
	if (res != 0) {
		mbedtls_ccm_free(&pres->aes_ccm_ctx);
		return -EINVAL;
	}

	/* encrypt payload */
	res = mbedtls_ccm_encrypt_and_tag(&pres->aes_ccm_ctx, payload_len,
					pres->master_enc_nonce, OPTIGA_PRE_AES128_NONCE_LEN,
					pres->assoc_data_buf, OPTIGA_PRE_ASSOC_DATA_LEN,
					payload,
					packet,
					packet + payload_len, OPTIGA_PRE_MAC_LEN);

	mbedtls_ccm_free(&pres->aes_ccm_ctx);

	if(res != 0) {
		return -EINVAL;
	}

	*out_len = OPTIGA_PRE_OVERHEAD + payload_len;
	return 0;
}

int optiga_pre_assemble_finished(struct present_layer *pres)
{
	/* Use handshake buffer */
	struct optiga_pre_handshake_buf *hs_buf = &pres->buf.hs;

	const u8_t sctr = OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE | OPTIGA_PRE_SCTR_PROTOCOL_HS_FINISHED;
	const u8_t *sseq = &pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];

	/* Assemble handshake payload */
	memcpy(hs_buf->scratch2, hs_buf->rnd, OPTIGA_PRE_RND_LEN);
	memcpy(hs_buf->scratch2 + OPTIGA_PRE_RND_LEN, sseq, OPTIGA_PRE_SEQ_LEN);

	pres->buf.hs.scratch_len = OPTIGA_PRE_SCRATCH_LEN;
	return optiga_pre_encrypt(pres, sctr, sseq, hs_buf->scratch2, OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN, pres->buf.hs.scratch, &pres->buf.hs.scratch_len);
}

int optiga_pre_decrypt(struct present_layer *pres, const u8_t *in_buf, size_t in_len, u8_t *payload, size_t *payload_len)
{
	if (in_len < OPTIGA_PRE_OVERHEAD) {
		/* Unexpected length */
		return -EINVAL;
	}

	const size_t buf_len = in_len - OPTIGA_PRE_OVERHEAD;
	if (buf_len > *payload_len) {
		/* Not enough memory in output buffer */
		return -EINVAL;
	}

	const u8_t *packet = in_buf;

	/* SCTR field */
	u8_t sctr = *packet;
	packet += OPTIGA_PRE_SCTR_LEN;

	/* SEQ field */
	const u8_t *seq = packet;
	packet += OPTIGA_PRE_SEQ_LEN;

	/* Assemble associated data */
	optiga_pre_assemble_assoc_data(pres, sctr, seq, buf_len);

	mbedtls_ccm_init(&pres->aes_ccm_ctx);
	int res = mbedtls_ccm_setkey(&pres->aes_ccm_ctx, MBEDTLS_CIPHER_ID_AES,
					pres->master_dec_key,
					OPTIGA_PRE_AES128_KEY_LEN*8);
	if (res != 0) {
		mbedtls_ccm_free(&pres->aes_ccm_ctx);
		return -EINVAL;
	}

	res = mbedtls_ccm_auth_decrypt(&pres->aes_ccm_ctx, buf_len,
						pres->master_dec_nonce, OPTIGA_PRE_AES128_NONCE_LEN,
						pres->assoc_data_buf, OPTIGA_PRE_ASSOC_DATA_LEN,
						packet,
						payload,
						packet + buf_len, OPTIGA_PRE_MAC_LEN);

	mbedtls_ccm_free(&pres->aes_ccm_ctx);

	if (res != 0) {
		/* decryption/authentication failure */
		return -EINVAL;
	}

	*payload_len = buf_len;
	return 0;
}

int optiga_pre_parse_finished(struct present_layer *pres)
{
	/* Use handshake buffer */
	struct optiga_pre_handshake_buf *hs_buf = &pres->buf.hs;

	if (hs_buf->scratch_len != (OPTIGA_PRE_SCTR_LEN + OPTIGA_PRE_SEQ_LEN + OPTIGA_PRE_HS_FINISH_PAYLOAD_LEN + OPTIGA_PRE_MAC_LEN)) {
		/* Unexpected length */
		return -EINVAL;
	}

	if (hs_buf->scratch[OPTIGA_PRE_SCTR_OFFS] != (OPTIGA_PRE_SCTR_PROTOCOL_HANDSHAKE | OPTIGA_PRE_SCTR_PROTOCOL_HS_FINISHED)) {
		/* Unexpected message */
		return -EINVAL;
	}

	const u8_t* mseq = &hs_buf->scratch[OPTIGA_PRE_SCTR_LEN];

	/* Put MSEQ into master decryption nonce */
	memcpy(&pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], mseq, OPTIGA_PRE_SEQ_LEN);

	hs_buf->scratch2_len = OPTIGA_PRE_SCRATCH_LEN;
	int res = optiga_pre_decrypt(pres, hs_buf->scratch, hs_buf->scratch_len, hs_buf->scratch2, &hs_buf->scratch2_len);
	if (res != 0) {
		/* decryption/authentication failure */
		return -EINVAL;
	}

	if (memcmp(hs_buf->scratch2, hs_buf->rnd, OPTIGA_PRE_RND_LEN) != 0) {
		/* RND value doesn't match first received value */
		return -EINVAL;
	}

	/*
	 * Master Encrypt Nonce and MSEQ belong togther for Record Exchange,
	 * but atm Master Encrypt Nonce and SSEQ are concatenated in memory,
	 * so we need to swap MSEQ and SSEQ now.
	 * Use scratch as temporary buffer.
	 */

	memcpy(hs_buf->scratch, &pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], OPTIGA_PRE_SEQ_LEN);
	memcpy(&pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], &pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], OPTIGA_PRE_SEQ_LEN);
	memcpy(&pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], hs_buf->scratch, OPTIGA_PRE_SEQ_LEN);

	return 0;
}

int optiga_pre_do_handshake(struct device *dev)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	/* Enable Presentation layer in NETTRAN */
	optiga_nettran_presence_enable(dev);

	/* Only pre-shared key implemented */
	pres->pver = OPTIGA_PRE_PVER_PRE_SHARED;

	/* Destroy handshake and data */
	mbedtls_platform_zeroize(&pres->buf, sizeof(pres->buf));

	/* Use handshake buffer */
	struct optiga_pre_handshake_buf *hs_buf = &pres->buf.hs;

	/* First step: request RND and SSEQ */
	optiga_pre_assemble_hello(pres);

	int res = optiga_nettran_send_apdu(dev, hs_buf->scratch, hs_buf->scratch_len);
	if (res != 0) {
		goto cleanup;
	}

	/* Receive RND and SSEQ */
	hs_buf->scratch_len = OPTIGA_PRE_SCRATCH_LEN;
	res = optiga_nettran_recv_apdu(dev, hs_buf->scratch, &hs_buf->scratch_len);
	if (res != 0) {
		goto cleanup;
	}

	/* Parse Hello from Slave */
	res = optiga_pre_parse_hello(pres);
	if (res != 0) {
		goto cleanup;
	}

	/* Derive master and slave encrypt/decrypt keys */
	res = optiga_pre_derive_keys(pres);
	if (res != 0) {
		goto cleanup;
	}

	/* Prepare final handshake message to Slave */
	res = optiga_pre_assemble_finished(pres);
	if (res != 0) {
		goto cleanup;
	}

	/* send to OPTIGA */
	res = optiga_nettran_send_apdu(dev, hs_buf->scratch, hs_buf->scratch_len);
	if (res != 0) {
		goto cleanup;
	}

	/* Receive final handshake message from OPTIGA */
	hs_buf->scratch_len = OPTIGA_PRE_SCRATCH_LEN;
	res = optiga_nettran_recv_apdu(dev, hs_buf->scratch, &hs_buf->scratch_len);
	if (res != 0) {
		goto cleanup;
	}

	res = optiga_pre_parse_finished(pres);
	if (res != 0) {
		goto cleanup;
	}

	/* Destroy handshake data */
	mbedtls_platform_zeroize(&pres->buf, sizeof(pres->buf));

	LOG_INF("Handshake finished successfully");

	return 0;

	/* Remove all generated crypographic keys */
	cleanup:
		optiga_pre_clear_keys(pres);
		return res;
}

static int optiga_pre_decrypt_apdu(struct present_layer *pres, u8_t *buf, size_t *len)
{
	u8_t* sseq = &pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];

	/* Increment Sequence numbers for exchanged message */
	if (!optiga_pre_seq_inc(sseq)) {
		/* We MUST NOT overflow the nonce */
		return -EIO;
	}

	int res = optiga_pre_decrypt(pres, pres->buf.op.encrypted_apdu, pres->buf.op.encrypted_apdu_len, buf, len);
	if (res != 0) {
		return res;
	}

	return 0;
}

int optiga_pre_recv_apdu(struct device *dev, u8_t *apdu, size_t *len)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	const bool encrypted = optiga_nettran_presence_get(dev);

	if (encrypted) {
		pres->buf.op.encrypted_apdu_len = OPTIGA_PRE_MAX_ENC_APDU_LEN;
		int res = optiga_nettran_recv_apdu(dev, pres->buf.op.encrypted_apdu, &pres->buf.op.encrypted_apdu_len);
		if (res != 0) {
			return res;
		}

		return optiga_pre_decrypt_apdu(pres, apdu, len);
	} else {
		return optiga_nettran_recv_apdu(dev, apdu, len);
	}
}

static int optiga_pres_encrypt_apdu(struct present_layer *pres, const u8_t *apdu, size_t len)
{
	u8_t *mseq = &pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];

	if (!optiga_pre_seq_inc(mseq)) {
		/* We MUST NOT overflow the nonce */
		return -EIO;
	}

	const u8_t sctr = OPTIGA_PRE_SCTR_PROTOCOL_REC_EXCHG | OPTIGA_PRE_SCTR_PROTECTION_MASTER | OPTIGA_PRE_SCTR_PROTECTION_SLAVE;
	pres->buf.op.encrypted_apdu_len = OPTIGA_PRE_MAX_ENC_APDU_LEN;
	int res = optiga_pre_encrypt(pres, sctr, mseq, apdu, len, pres->buf.op.encrypted_apdu, &pres->buf.op.encrypted_apdu_len);

	if(res != 0) {
		return -EINVAL;
	}

	return 0;
}

int optiga_pre_send_apdu(struct device *dev, const u8_t *apdu, size_t len)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	const u8_t *send_data = apdu;
	const size_t *send_len = &len;

	if (optiga_nettran_presence_get(dev)) {
		int res = optiga_pres_encrypt_apdu(pres, apdu, len);
		if (res != 0) {
			/* Error during encryption */
			return res;
		}

		send_data = pres->buf.op.encrypted_apdu;
		send_len = &pres->buf.op.encrypted_apdu_len;
	}

	return optiga_nettran_send_apdu(dev, send_data, *send_len);
}

int optiga_pre_save_ctx(struct device *dev)
{
	if (!optiga_nettran_presence_get(dev)) {
		LOG_INF("Shield not active");
		return 0;
	}

	u8_t sctr = OPTIGA_PRE_SCTR_PROTOCOL_MANAGE_CTX | OPTIGA_PRE_SCTR_MSG_CTX_SAVE;
	int res = optiga_nettran_send_apdu(dev, &sctr, 1);
	if (res != 0) {
		return res;
	}

	size_t response_len = 1;
	res = optiga_nettran_recv_apdu(dev, &sctr, &response_len);

	if (sctr != (OPTIGA_PRE_SCTR_PROTOCOL_MANAGE_CTX | OPTIGA_PRE_SCTR_MSG_CTX_SAVED)) {
		return -EIO;
	}

	return 0;
}

int optiga_pre_restore_ctx(struct device *dev)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	__ASSERT(optiga_nettran_presence_get(dev), "Shield must be active");

	u8_t packet_buf[5] = {0};
	u8_t *packet = packet_buf;

	*packet = OPTIGA_PRE_SCTR_PROTOCOL_MANAGE_CTX | OPTIGA_PRE_SCTR_MSG_CTX_RESTORE;
	packet += OPTIGA_PRE_SCTR_LEN;

	memcpy(packet, &pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], OPTIGA_PRE_SEQ_LEN);
	int res = optiga_nettran_send_apdu(dev, packet_buf, 5);
	if (res != 0) {
		return res;
	}

	size_t response_len = 5;
	res = optiga_nettran_recv_apdu(dev, packet_buf, &response_len);
	packet = packet_buf;

	if (*packet != (OPTIGA_PRE_SCTR_PROTOCOL_MANAGE_CTX | OPTIGA_PRE_SCTR_MSG_CTX_RESTORED)) {
		/* Unexpected response */
		return -EIO;
	}

	packet += OPTIGA_PRE_SCTR_LEN;

	if (memcmp(packet, &pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS], OPTIGA_PRE_SEQ_LEN) != 0) {
		/* Unexpected sequence number */
		return -EIO;
	}

	return 0;
}

bool optiga_pre_need_rehandshake(struct device *dev)
{
	struct optiga_data *data = dev->driver_data;
	struct present_layer *pres = &data->present;

	const u8_t *mseq = &pres->master_enc_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];
	const u8_t *sseq = &pres->master_dec_nonce[OPTIGA_PRE_NONCE_SEQ_OFFS];

	return optiga_pre_seq_max(mseq) || optiga_pre_seq_max(sseq);
}