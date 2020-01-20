/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IFX_OPTIGA_TRUST_X_H_
#define IFX_OPTIGA_TRUST_X_H_

#include <device.h>
#include <zephyr.h>
#include <zephyr/types.h>

#include <drivers/crypto/optiga.h>

// TODO(chr): find the maximum APDU size value
#define IFX_OPTIGA_TRUST_MAX_APDU_SIZE 1600

struct ifx_optiga_trust_ctx {
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
int ifx_optiga_trust_init(struct ifx_optiga_trust_ctx *ctx, struct device *dev, u8_t *apdu_buf, size_t apdu_buf_len);

/*
 * @brief Free and unbind the command context
 * @param ctx context to free
 */
void ifx_optiga_trust_free(struct ifx_optiga_trust_ctx *ctx);

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
int ifx_optiga_trust_get_data_object(struct ifx_optiga_trust_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len);

/*
 * @brief Write data to a data object in the OPTIGA
 *
 * @param ctx Command context to use
 * @param oid Object ID to write to
 * @param erase If true, erase data object before writing
 * @param offs Number of bytes to skip from the beginning of the data object
 * @param buf Data to write
 * @param len length of buf
 * @return 0 on success, error code otherwise
 */
int ifx_optiga_trust_set_data_object(struct ifx_optiga_trust_ctx *ctx, u16_t oid, bool erase, size_t offs, const u8_t *buf, size_t len);


#define IFX_OPTIGA_TRUST_NIST_P256_PUB_KEY_LEN 64
#define IFX_OPTIGA_TRUST_NIST_P384_PUB_KEY_LEN 96

enum IFX_OPTIGA_TRUST_ALGORITHM {
	IFX_OPTIGA_TRUST_ALGORITHM_NIST_P256 = 0x03,
	IFX_OPTIGA_TRUST_ALGORITHM_NIST_P384 = 0x04,
	IFX_OPTIGA_TRUST_ALGORITHM_SHA256	= 0xE2
};

enum IFX_OPTIGA_TRUST_KEY_USAGE_FLAG {
	IFX_OPTIGA_TRUST_KEY_USAGE_FLAG_AUTH	= 0x01,
	IFX_OPTIGA_TRUST_KEY_USAGE_FLAG_ENC = 0x02,
	IFX_OPTIGA_TRUST_KEY_USAGE_FLAG_HOST_FW_UPDATE = 0x04,
	IFX_OPTIGA_TRUST_KEY_USAGE_FLAG_DEV_MGMT = 0x08,
	IFX_OPTIGA_TRUST_KEY_USAGE_FLAG_SIGN = 0x10,
};

/*
 * @brief Generate an ECDSA key pair and export the public key
 *
 * @param ctx Command context to use
 * @param oid Object ID to store the private key
 * @param alg Type of key pair to generate
 * @param key_usage Combination of IFX_OPTIGA_TRUST_KEY_USAGE_FLAG, see Solution Reference Manual, Table 39 for their meaning
 * @param pub_key Output buffer for the pulic key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @return 0 on success, error code otherwise
 *
 * @note The size of the public key buffer must match the selected algorithm or be bigger.
 */
int ifx_optiga_trust_gen_key_ecdsa(struct ifx_optiga_trust_ctx *ctx, u16_t oid, enum IFX_OPTIGA_TRUST_ALGORITHM alg,
				enum IFX_OPTIGA_TRUST_KEY_USAGE_FLAG key_usage, u8_t *pub_key, size_t *pub_key_len);

#define IFX_OPTIGA_TRUST_NIST_P256_SIGNATURE_LEN 64
#define IFX_OPTIGA_TRUST_NIST_P384_SIGNATURE_LEN 96

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
int ifx_optiga_trust_sign_ecdsa(struct ifx_optiga_trust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len);

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
int ifx_optiga_trust_verify_ecdsa_oid(struct ifx_optiga_trust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, const u8_t *signature, size_t signature_len);

#endif /* IFX_OPTIGA_TRUST_X_H_ */