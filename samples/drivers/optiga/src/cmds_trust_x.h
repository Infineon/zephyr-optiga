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

/*
 * @brief Initialize a command context and bind it to a device
 *
 * @param ctx context to initialize
 * @param dev device to bind the context to
 * @param apdu_buf send and receive buffer for the APDU
 * @param apdu_buf_len length of apdu_buf
 */
int cmds_trust_x_init(struct cmds_ctx *ctx, struct device *dev, u8_t *apdu_buf, size_t apdu_buf_len);

/*
 * @brief Free and unbind the command context
 * @param ctx context to free
 */
void cmds_trust_x_free(struct cmds_ctx *ctx);

/*
 * @brief Read data from a data object in the OPTIGA
 *
 * @param ctx Command context to use
 * @param oid Object ID to read from
 * @param offs Number of bytes to skip from the beginning of the data object
 * @param buf Output buffer for the read data
 * @param len Must be set to the length of buf and returns the number of data bytes read
 * @return 0 on success, error code otherwise
 */
int cmds_trust_x_get_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len);

/*
 * @brief Write data to a data object in the OPTIGA
 *
 * @param ctx Command context to use
 * @param oid Object ID to write to
 * @param offs Number of bytes to skip from the beginning of the data object
 * @param buf Data to write
 * @param len length of buf
 * @return 0 on success, error code otherwise
 */
int cmds_trust_x_set_data_object(struct cmds_ctx *ctx, u16_t oid, size_t offs, const u8_t *buf, size_t len);


#define CMDS_TRUSTX_NIST_P256_PUB_KEY_LEN 64
#define CMDS_TRUSTX_NIST_P384_PUB_KEY_LEN 96

enum CMDS_TRUSTX_ALGORITHM {
	CMDS_TRUSTX_ALGORITHM_NIST_P256 = 0x03,
	CMDS_TRUSTX_ALGORITHM_NIST_P384 = 0x04,
	CMDS_TRUSTX_ALGORITHM_SHA256	= 0xE2
};

/*
 * @brief Generate an ECDSA key pair and export the public key
 *
 * @param ctx Command context to use
 * @param oid Object ID to store the private key
 * @param alg Type of key pair to generate
 * @param pub_key Output buffer for the pulic key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @return 0 on success, error code otherwise
 *
 * @note The size of the public key buffer must match the selected algorithm or be bigger.
 */
int cmds_trust_x_gen_key_ecdsa(struct cmds_ctx *ctx, u16_t oid, enum CMDS_TRUSTX_ALGORITHM alg, u8_t *pub_key, size_t *pub_key_len);

#define CMDS_TRUSTX_NIST_P256_SIGNATURE_LEN 64
#define CMDS_TRUSTX_NIST_P384_SIGNATURE_LEN 96

/*
 * @brief Sign a digest using a private key in the OPTIGA
 *
 * @param ctx Command context to use
 * @param oid Object ID of the private key to use
 * @param digest Digest to sign
 * @param digest_len Length of digest
 * @param signature Output buffer for the signature
 * @param signature_len Length of signature buffer, contains length of signature afterwards.
 * @return 0 on success, error code otherwise
 */
int cmds_trust_x_sign_ecdsa(struct cmds_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len);

/*
 * @brief Verify a signature using a public key in the OPTIGA
 *
 * @param ctx Command context to use
 * @param oid Object ID of the public key to use
 * @param digest Digest to verify the signature of
 * @param digest_len Length of digest
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return 0 if the signature matches, error code otherwise
 */
int cmds_trust_x_verify_ecdsa_oid(struct cmds_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, const u8_t *signature, size_t signature_len);

#endif /* CMDS_TRUST_X_H_ */