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
int ifx_optiga_data_get(struct ifx_optiga_trust_ctx *ctx, u16_t oid, size_t offs, u8_t *buf, size_t *len);

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
int ifx_optiga_data_set(struct ifx_optiga_trust_ctx *ctx, u16_t oid, bool erase, size_t offs, const u8_t *buf, size_t len);


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
 * @param pub_key Output buffer for the public key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @return 0 on success, error code otherwise
 *
 * @note The size of the public key buffer must match the selected algorithm or be bigger.
 */
int ifx_optiga_ecc_key_pair_gen_oid(struct ifx_optiga_trust_ctx *ctx, u16_t oid, enum IFX_OPTIGA_TRUST_ALGORITHM alg,
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
int ifx_optiga_ecdsa_sign_oid(struct ifx_optiga_trust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, u8_t *signature, size_t signature_len);

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
int ifx_optiga_ecdsa_verify_oid(struct ifx_optiga_trust_ctx *ctx, u16_t oid, const u8_t *digest, size_t digest_len, const u8_t *signature, size_t signature_len);

/* The following APIs are drafts for now */

/*
 * @brief Generate an ECDSA key pair and export private and public key
 *
 * @param ctx Command context to use
 * @param alg Type of key pair to generate
 * @param key_usage Combination of IFX_OPTIGA_TRUST_KEY_USAGE_FLAG, see Solution Reference Manual, Table 39 for their meaning
 * @param priv_key Output buffer for the private key
 * @param priv_key_len length of pub_key, contains the length of the private key
 * @param pub_key Output buffer for the public key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @return 0 on success, error code otherwise
 *
 * @note The size of the public and private key buffers must match the selected algorithm or be bigger.
 */
int ifx_optiga_ecc_key_pair_gen(struct ifx_optiga_trust_ctx *ctx,
				enum IFX_OPTIGA_TRUST_ALGORITHM alg,
				enum IFX_OPTIGA_TRUST_KEY_USAGE_FLAG key_usage,
				u8_t* priv_key, size_t * priv_key_len,
				u8_t *pub_key, size_t *pub_key_len);

/*
 * @brief Perform an ECDH operation on a shared secret to derive a key
 *
 * @param ctx Command context to use
 * @param shared_secret_oid OID of the shared secret to use for key derivation
 * @param deriv_data Shared secret derivation data
 * @param deriv_data_len Length of deriv_data
 * @param key Output buffer for the derived key
 * @param key_len Length of key
 * @return 0 on success, error code otherwise
 */
int ifx_optiga_ecdh_compute(struct ifx_optiga_trust_ctx *ctx, u16_t shared_secret_oid,
				const u8_t *deriv_data, size_t deriv_data_len,
				u8_t *key, size_t key_len);

/*
 * @brief Perform an ECDH operation on a shared secret to derive a key and store it in a session context
 *
 * @param ctx Command context to use
 * @param shared_secret_oid OID of the shared secret to use for key derivation
 * @param deriv_data Shared secret derivation data
 * @param deriv_data_len Length of deriv_data
 * @param key_len Length of key
 * @param key_oid OID to store the derived key
 * @return 0 on success, error code otherwise
 */
int ifx_optiga_ecdh_compute_oid(struct ifx_optiga_trust_ctx *ctx, u16_t shared_secret_oid,
				const u8_t *deriv_data, size_t deriv_data_len,
				size_t key_len, u16_t key_oid);

/*
 * @brief Verify a signature using a public key provided by the host
 *
 * @param ctx Command context to use
 * @param alg Algorithm identifier of the public key
 * @param pub_key Output buffer for the public key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @param digest Digest to verify the signature of
 * @param digest_len Length of digest
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return 0 if the signature matches, error code otherwise
 */
int ifx_optiga_ecdsa_verify_host(struct ifx_optiga_trust_ctx *ctx, enum IFX_OPTIGA_TRUST_ALGORITHM alg,
				const u8_t *pub_key, size_t pub_key_len,
				const u8_t *digest, size_t digest_len,
				const u8_t *signature, size_t signature_len);

int ifx_optiga_metadata_get(struct ifx_optiga_trust_ctx *ctx);

int ifx_optiga_metadata_set(struct ifx_optiga_trust_ctx *ctx);

#define IFX_OPTIGA_TRUST_SHA256_DIGEST_LEN 32

int ifx_optiga_hash_sha256(struct ifx_optiga_trust_ctx *ctx);

/*
 * @brief Hash data from an OID
 *
 * @param ctx Command context to use
 * @param oid OID to read the data to has
 * @param offs Number of bytes to skip befor hashing data
 * @param len Number of bytes to hash
 * @param digest Computed digest
 * @param digest_len Length of digest, contains the length of the computed digest afterwards
 * @return 0 if the signature matches, error code otherwise
 */
int ifx_optiga_hash_sha256_oid(struct ifx_optiga_trust_ctx *ctx,
				u16_t oid, size_t offs, size_t len,
				u8_t *digest, size_t *digest_len);

int ifx_optiga_rng_generate(struct ifx_optiga_trust_ctx *ctx);

int ifx_optiga_tls1_2_prf_sha256_compute(struct ifx_optiga_trust_ctx *ctx);

int ifx_optiga_set_auth_scheme(struct ifx_optiga_trust_ctx *ctx);

int ifx_optiga_get_auth_msg(struct ifx_optiga_trust_ctx *ctx);

int ifx_optiga_set_auth_msg(struct ifx_optiga_trust_ctx *ctx);

int ifx_optiga_proc_downlink_msg(struct ifx_optiga_trust_ctx *ctx);

int ifx_optiga_proc_uplink_msg(struct ifx_optiga_trust_ctx *ctx);

#endif /* IFX_OPTIGA_TRUST_X_H_ */