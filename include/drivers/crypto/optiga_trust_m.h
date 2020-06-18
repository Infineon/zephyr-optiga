/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_TRUST_M_H_
#define ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_TRUST_M_H_

#include <device.h>
#include <zephyr.h>
#include <zephyr/types.h>

#include <drivers/crypto/optiga_apdu.h>

#define OPTRUST_DATA_OBJECT_TYPE2_LEN	1500
#define OPTRUST_DATA_OBJECT_TYPE3_LEN	140
#define OPTRUST_PUB_KEY_CERT_LEN	1728
#define OPTRUST_COPROCESSOR_UID_LEN	26

/* Size of the APDU buffer to read the device certificate at once */
#define OPTRUST_CERT_READ_APDU_SIZE (OPTRUST_PUB_KEY_CERT_LEN + 4)
/* Size of the APDU buffer to read/write a large (type 2) data object at once */
#define OPTRUST_DATA_OBJECT_LARGE_APDU_SIZE (OPTRUST_DATA_OBJECT_TYPE2_LEN + 8)
/* Size of the APDU buffer to read/write a small (type 3) data object at once */
#define OPTRUST_DATA_OBJECT_SMALL_APDU_SIZE (OPTRUST_DATA_OBJECT_TYPE3_LEN + 8)

struct optrust_ctx {
	struct device *dev;
	uint8_t *apdu_buf;
	size_t apdu_buf_len;
	struct optiga_apdu apdu;
};

/*
 * See "Figure 29 - Overview Data and Key Store" for details.
 * Session Ccontexts are not defined, since they are handed out by optiga_session_acquire(...)
 */

/* Common Data Objects */
#define OPTRUST_OID_GLOBAL_LIFE_CYCLE_STATUS 0xE0C0
#define OPTRUST_OID_GLOBAL_SECURITY_STATUS 0xE0C1
#define OPTRUST_OID_COPROCESSOR_UID 0xE0C2
#define OPTRUST_OID_SLEEP_DELAY	0xE0C3
#define OPTRUST_OID_CURRENT_LIMIT 0xE0C4
#define OPTRUST_OID_SECURITY_EVENT_COUNTER 0xE0C5
#define OPTRUST_OID_MAX_COMM_BUFFER_SIZE 0xE0C6
#define OPTRUST_OID_ERROR_CODES 0xF1C2

/* Monotonic Counters */
#define OPTRUST_OID_MONOTONIC_COUNTER_1 0xE120
#define OPTRUST_OID_MONOTONIC_COUNTER_2 0xE121
#define OPTRUST_OID_MONOTONIC_COUNTER_3 0xE122
#define OPTRUST_OID_MONOTONIC_COUNTER_4 0xE123

/* ECC keys */
#define OPTRUST_OID_ECC_KEY_1 0xE0F0
#define OPTRUST_OID_ECC_KEY_2 0xE0F1
#define OPTRUST_OID_ECC_KEY_3 0xE0F2
#define OPTRUST_OID_ECC_KEY_4 0xE0F3

/* RSA keys */
#define OPTRUST_OID_RSA_KEY_1 0xE0FC
#define OPTRUST_OID_RSA_KEY_2 0xE0FD

/* Certificates */
#define OPTRUST_OID_PUB_KEY_CERT_1 0xE0E0
#define OPTRUST_OID_PUB_KEY_CERT_2 0xE0E1
#define OPTRUST_OID_PUB_KEY_CERT_3 0xE0E2
#define OPTRUST_OID_PUB_KEY_CERT_4 0xE0E3

#define OPTRUST_OID_TRUST_ANCHOR_1 0xE0E8
#define OPTRUST_OID_TRUST_ANCHOR_2 0xE0E9

#define OPTRUST_OID_TRUST_ANCHOR_8 0xE0EF

#define OPTRUST_OID_PLATFORM_BINDING_SECRET 0xE140

#define OPTRUST_OID_APPLICATION_LIFE_CYCLE_STATUS 0xF1C0
#define OPTRUST_OID_APPLICATION_SECURITY_STATUS 0xF1C1

/* Type 3, 140 bytes */
#define OPTRUST_OID_DATA_OBJECT_1	0xF1D0
#define OPTRUST_OID_DATA_OBJECT_2	0xF1D1
#define OPTRUST_OID_DATA_OBJECT_3	0xF1D2
#define OPTRUST_OID_DATA_OBJECT_4	0xF1D3
#define OPTRUST_OID_DATA_OBJECT_5	0xF1D4
#define OPTRUST_OID_DATA_OBJECT_6	0xF1D5
#define OPTRUST_OID_DATA_OBJECT_7	0xF1D6
#define OPTRUST_OID_DATA_OBJECT_8	0xF1D7
#define OPTRUST_OID_DATA_OBJECT_9	0xF1D8
#define OPTRUST_OID_DATA_OBJECT_10	0xF1D9
#define OPTRUST_OID_DATA_OBJECT_11	0xF1DA
#define OPTRUST_OID_DATA_OBJECT_12	0xF1DB

/* Type 2, 1500 bytes */
#define OPTRUST_OID_DATA_OBJECT_17	0xF1E0
#define OPTRUST_OID_DATA_OBJECT_18	0xF1E1

/* From "Table 6 - Error Codes" */
enum OPTRUST_M_ERROR {
	OPTRUST_M_ERROR_NO_ERROR = 0x00,
	OPTRUST_M_ERROR_INVALID_OID = 0x01,
	OPTRUST_M_ERROR_INVALID_PASSWORD = 0x02,
	OPTRUST_M_ERROR_INVALID_PARAM = 0x03,
	OPTRUST_M_ERROR_INVALID_LENGTH = 0x04,
	OPTRUST_M_ERROR_INVALID_PARAM_IN_DATA = 0x05,
	OPTRUST_M_ERROR_INTERNAL = 0x06,
	OPTRUST_M_ERROR_ACCESS_CONDITION = 0x07,
	OPTRUST_M_ERROR_DATA_OBJECT_BOUNDARY = 0x08,
	OPTRUST_M_ERROR_METADATA_TRUNCATED = 0x09,
	OPTRUST_M_ERROR_INVALID_COMMAND = 0x0A,
	OPTRUST_M_ERROR_OUT_OF_SEQUENCE = 0x0B,
	OPTRUST_M_ERROR_COMMAND_NOT_AVAILABLE = 0x0C,
	OPTRUST_M_ERROR_NO_MEMORY = 0x0D,
	OPTRUST_M_ERROR_COUNTER_LIMIT = 0x0E,
	OPTRUST_M_ERROR_INVALID_MANIFEST = 0x0F,
	OPTRUST_M_ERROR_INVALID_PAYLOAD_VERSION = 0x10,
	OPTRUST_M_ERROR_INVALID_HANDSHAKE_MESSAGE = 0x21,
	OPTRUST_M_ERROR_VERION_MISMATCH = 0x22,
	OPTRUST_M_ERROR_UNSUPPORTED_CIPHER = 0x23,
	OPTRUST_M_ERROR_UNSUPPORTED_EXTENSION = 0x24,
	OPTRUST_M_ERROR_INVALID_TRUST_ANCHOR = 0x26,
	OPTRUST_M_ERROR_TRUST_ANCHOR_EXPIRED = 0x27,
	OPTRUST_M_ERROR_UNSUPPORTED_TRUST_ANCHOR = 0x28,
	OPTRUST_M_ERROR_INVALID_CERT = 0x29,
	OPTRUST_M_ERROR_UNSUPPORTED_CERT_ALG = 0x2A,
	OPTRUST_M_ERROR_CERT_EXPIRED = 0x2B,
	OPTRUST_M_ERROR_SIGNATURE_VERIFY = 0x2C,
	OPTRUST_M_ERROR_INTEGRITY_VERIFY = 0x2D,
	OPTRUST_M_ERROR_DECRYPTION = 0x2E,
};


/**
 * @brief Initialize a command context and bind it to a device
 *
 * @param ctx context to initialize
 * @param dev device to bind the context to
 * @param apdu_buf send and receive buffer for the APDU
 * @param apdu_buf_len length of apdu_buf
 */
int optrust_init(struct optrust_ctx *ctx, struct device *dev, uint8_t *apdu_buf, size_t apdu_buf_len);

/**
 * @brief Deallocate all resources and unbind the command context
 * @param ctx context to free
 */
void optrust_deinit(struct optrust_ctx *ctx);

/**
 * @brief Request a wake-lock token
 * @param ctx Context to use
 * @param token Wake-lock token, to later release the wake lock again
 * @return 0 on success, error code otherwise
 */
int optrust_wake_lock_acquire(struct optrust_ctx *ctx, int *token);

/**
 * @brief Return a wake-lock token
 * @param ctx Context to use
 * @param token Wake-lock token to release
 * @return 0 on success, error code otherwise
 */
void optrust_wake_lock_release(struct optrust_ctx *ctx, int token);

/**
 * @brief Request a session context for exclusive use
 * @param oid Returned OID of the assigned session context
 * @return 0 on success, error code otherwise
 */
int optrust_session_acquire(struct optrust_ctx *ctx, uint16_t *oid);

/**
 * @brief Return a session context
 * @param oid OID of the session context to return
 * @return 0 on success, error code otherwise
 */
int optrust_session_release(struct optrust_ctx *ctx, uint16_t oid);

/* Lenght of the pre-shared key for shielded connection */
#define OPTRUST_SHIELD_PSK_LEN 64

/**
 * @brief Start shielded connection to Trust M using a pre-shared key
 * @param psk Pre shared key
 * @param psk_len Length of psk
 * @return 0 on success, error code otherwise
 */
int optrust_shielded_connection_psk_start(struct optrust_ctx *ctx, const uint8_t *psk, size_t psk_len);

/**
 * @brief Read data from a data object in the OPTIGA
 *
 * @param ctx Command context to use
 * @param oid Object ID to read from
 * @param offs Number of bytes to skip from the beginning of the data object
 * @param buf Output buffer for the read data
 * @param len Must be set to the length of buf and returns the number of data bytes read
 * @return 0 on success, error code otherwise
 */
int optrust_data_get(struct optrust_ctx *ctx, uint16_t oid, size_t offs, uint8_t *buf, size_t *len);

/**
 * @brief Update a data object using the "Protected Update" mechanism
 *
 * @param ctx Command context to use
 * @param manifest Update Manifest to use
 * @param manifest_len Length of manifest
 * @param payload Payload for the update
 * @param payload_len Length of payload
 * @return 0 on success, error code otherwise
 *
 * @note See "Table 11 - SetObjectProtected" Coding for details
 */
int optrust_data_protected_update(struct optrust_ctx *ctx, const uint8_t *manifest, size_t manifest_len, const uint8_t *payload, size_t payload_len);

/**
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
int optrust_data_set(struct optrust_ctx *ctx, uint16_t oid, bool erase, size_t offs, const uint8_t *buf, size_t len);

#define OPTRUST_NIST_P256_SEC_KEY_LEN 32
#define OPTRUST_NIST_P384_SEC_KEY_LEN 48
#define OPTRUST_NIST_P256_PUB_KEY_LEN (OPTRUST_NIST_P256_SEC_KEY_LEN*2)
#define OPTRUST_NIST_P384_PUB_KEY_LEN (OPTRUST_NIST_P384_SEC_KEY_LEN*2)

enum OPTRUST_ALGORITHM {
    OPTRUST_ALGORITHM_NIST_P256 = 0x03,
    OPTRUST_ALGORITHM_NIST_P384 = 0x04,
    OPTRUST_ALGORITHM_RSA_1024	= 0x41,
    OPTRUST_ALGORITHM_RSA_2048	= 0x42,
    OPTRUST_ALGORITHM_SHA256	= 0xE2,
};

enum OPTRUST_KEY_USAGE_FLAG {
    OPTRUST_KEY_USAGE_FLAG_AUTH	= 0x01,
    OPTRUST_KEY_USAGE_FLAG_ENC = 0x02,
    OPTRUST_KEY_USAGE_FLAG_SIGN = 0x10,
    OPTRUST_KEY_USAGE_FLAG_KEY_AGREE = 0x20,
};

/**
 * @brief Generate an ECC key pair and export the public key
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
int optrust_ecc_gen_keys_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_ALGORITHM alg,
                enum OPTRUST_KEY_USAGE_FLAG key_usage, uint8_t *pub_key, size_t *pub_key_len);

/**
 * @brief Generate an ECDSA key pair and export private and public key
 *
 * @param ctx Command context to use
 * @param alg Type of key pair to generate
 * @param priv_key Output buffer for the private key
 * @param priv_key_len length of pub_key, contains the length of the private key
 * @param pub_key Output buffer for the public key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @return 0 on success, error code otherwise
 *
 * @note The size of the public and private key buffers must match the selected algorithm or be bigger.
 */
int optrust_ecc_gen_keys_ext(struct optrust_ctx *ctx,
				enum OPTRUST_ALGORITHM alg,
				uint8_t* priv_key, size_t * priv_key_len,
				uint8_t *pub_key, size_t *pub_key_len);


#define OPTRUST_NIST_P256_SIGNATURE_LEN 64
#define OPTRUST_NIST_P384_SIGNATURE_LEN 96

/**
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
int optrust_ecdsa_sign_oid(struct optrust_ctx *ctx, uint16_t oid, const uint8_t *digest, size_t digest_len, uint8_t *signature, size_t *signature_len);

/**
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
int optrust_ecdsa_verify_ext(struct optrust_ctx *ctx, enum OPTRUST_ALGORITHM alg,
				const uint8_t *pub_key, size_t pub_key_len,
				const uint8_t *digest, size_t digest_len,
				const uint8_t *signature, size_t signature_len);

/**
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
int optrust_ecdsa_verify_oid(struct optrust_ctx *ctx, uint16_t oid, const uint8_t *digest, size_t digest_len, const uint8_t *signature, size_t signature_len);

enum OPTRUST_RNG_TYPE {
	OPTRUST_RNG_TYPE_TRNG	= 0x00,
	OPTRUST_RNG_TYPE_DRNG	= 0x01,
};

/**
 * @brief Generate random bytes
 * @param ctx Command context to use
 * @param type Type of the RNG to use
 * @param rnd Output buffer for the random bytes
 * @param rnd_len Size of the output buffer
 * @return 0 on success, error code otherwise
 */
int optrust_rng_gen_ext(struct optrust_ctx *ctx, enum OPTRUST_RNG_TYPE type, uint8_t *rnd, size_t rnd_len);

/**
 * @brief Generate random bytes and store them in an OID
 * @param ctx Command context to use
 * @param rnd_len Number of random bytes to generate
 * @param prepend Data to prepend to random data, may be NULL
 * @param prepend_len Length of prepend, may be 0
 * @return 0 on success, error code otherwise
 *
 * @note This function is intended to generate a Pre-Master Secret and limited in its functionality. See "Table 12 - GetRandom Coding" for details.
 */
int optrust_rng_gen_oid(struct optrust_ctx *ctx, uint16_t oid, size_t rnd_len, const uint8_t *prepend, size_t prepend_len);

#define OPTRUST_ECDH_SHARED_SECRET_NIST_P256_LEN 32
#define OPTRUST_ECDH_SHARED_SECRET_NIST_P384_LEN 48

/**
 * @brief Perform an ECDH operation on a public and private key to derive a shared secret and store it in a session context
 *
 * @param ctx Command context to use
 * @param sec_key_oid OID of the private key to use for key derivation
 * @param alg Algorithm identifier of the Public key, must be OPTRUST_ALGORITHM_NIST_P256 or OPTRUST_ALGORITHM_NIST_P383
 * @param pub_key Public key
 * @param pub_key_len Length of pub_key
 * @param shared_secret Buffer to store the shared secret
 * @param shared_secret_len Length of shared_secret, contains bytes written afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_ecdh_calc_ext(struct optrust_ctx *ctx, uint16_t sec_key_oid,
				enum OPTRUST_ALGORITHM alg,
				const uint8_t *pub_key, size_t pub_key_len,
				uint8_t* shared_secret, size_t* shared_secret_len);

/**
 * @brief Perform an ECDH operation on a public and private key to derive a shared secret and store it in a session context
 *
 * @param ctx Command context to use
 * @param sec_key_oid OID of the private key to use for key derivation
 * @param alg Algorithm identifier of the Public key, must be OPTRUST_ALGORITHM_NIST_P256 or OPTRUST_ALGORITHM_NIST_P383
 * @param pub_key Public key
 * @param pub_key_len Length of pub_key
 * @param shared_secret_oid OID to store the shared secret
 * @return 0 on success, error code otherwise
 */
int optrust_ecdh_calc_oid(struct optrust_ctx *ctx, uint16_t sec_key_oid,
				enum OPTRUST_ALGORITHM alg,
				const uint8_t *pub_key, size_t pub_key_len,
				uint16_t shared_secret_oid);

#define OPTRUST_SHA256_DIGEST_LEN 32

/**
 * @brief Hash data passed by the host
 *
 * @param ctx Command context to use
 * @param data Data to hash
 * @param data_len Length of data
 * @param digest Output buffer for the computed digest
 * @param digest_len Length of digest, contains the length of the computed digest afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_sha256_ext(struct optrust_ctx *ctx, const uint8_t* data, size_t data_len,
                       uint8_t *digest, size_t *digest_len);

/**
 * @brief Hash data from an OID
 *
 * @param ctx Command context to use
 * @param oid OID to read the data to hash
 * @param offs Number of bytes to skip befor hashing data
 * @param len Number of bytes to hash
 * @param digest Computed digest
 * @param digest_len Length of digest, contains the length of the computed digest afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_sha256_oid(struct optrust_ctx *ctx,
				uint16_t oid, size_t offs, size_t len,
				uint8_t *digest, size_t *digest_len);


/**
 * @brief Read metadata from a data object
 * @param ctx Command context to use
 * @param oid OID of the data object
 * @param data Output buffer for the data object
 * @param data_len Length of the output buffer, contains length of metadata afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_metadata_get(struct optrust_ctx *ctx, uint16_t oid, uint8_t *data, size_t *data_len);

/**
 * @brief Set metadata of a data object
 * @param ctx Command context to use
 * @param oid OID of the data object
 * @param data metadata to write
 * @param data_len length of data
 * @return 0 on success, error code otherwise
 */
int optrust_metadata_set(struct optrust_ctx *ctx, uint16_t oid, const uint8_t *data, size_t data_len);

/**
 * @brief Increment a monotonic counter
 * @param ctx Command context to use
 * @param oid OID of the monotonic counter
 * @param inc Value by which to increment the counter
 * @return 0 on success, error code otherwise
 */
int optrust_counter_inc(struct optrust_ctx *ctx, uint16_t oid, uint8_t inc);

/* See Table 26 - Signature Schemes for more information */
enum OPTRUST_SIGNATURE_SCHEME {
	OPTRUST_SIGNATURE_SCHEME_PKCS1_v1_5_SHA256	= 0x01,
	OPTRUST_SIGNATURE_SCHEME_PKCS1_v1_5_SHA384	= 0x02,
};

#define OPTRUST_RSA1024_SIGNATURE_LEN 128
#define OPTRUST_RSA2048_SIGNATURE_LEN 256

/**
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
int optrust_rsa_sign_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_SIGNATURE_SCHEME scheme, const uint8_t *digest, size_t digest_len, uint8_t *signature, size_t *signature_len);

#define OPTRUST_RSA1024_PUB_KEY_LEN 144
#define OPTRUST_RSA2048_PUB_KEY_LEN 275

/**
 * @brief Generate a RSA key pair and export the public key
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
int optrust_rsa_gen_keys_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_ALGORITHM alg,
                enum OPTRUST_KEY_USAGE_FLAG key_usage, uint8_t *pub_key, size_t *pub_key_len);

#define OPTRUST_RSA1024_SEC_KEY_LEN (128+3)
#define OPTRUST_RSA2048_SEC_KEY_LEN (256+4)
/**
 * @brief Generate a RSA key pair and export private and public key
 *
 * @param ctx Command context to use
 * @param alg Type of key pair to generate
 * @param sec_key Output buffer for the private key
 * @param sec_key_len length of pub_key, contains the length of the private key
 * @param pub_key Output buffer for the public key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @return 0 on success, error code otherwise
 *
 * @note The size of the public and private key buffers must match the selected algorithm or be bigger.
 */
int optrust_rsa_gen_keys_ext(struct optrust_ctx *ctx, enum OPTRUST_ALGORITHM alg,
				uint8_t *sec_key, size_t *sec_key_len,
				uint8_t *pub_key, size_t *pub_key_len);

/**
 * @brief Verify a RSA signature using a public key provided by the host
 *
 * @param ctx Command context to use
 * @param scheme Signature scheme to use, see Table 26 - Signature Schemes for details
 * @param alg Algorithm identifier of the public key
 * @param pub_key Output buffer for the public key
 * @param pub_key_len length of pub_key, contains the length of the public key
 * @param digest Digest to verify the signature of
 * @param digest_len Length of digest
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return 0 if the signature matches, error code otherwise
 */
int optrust_rsa_verify_ext(struct optrust_ctx *ctx, enum OPTRUST_SIGNATURE_SCHEME scheme,
				enum OPTRUST_ALGORITHM alg, const uint8_t *pub_key, size_t pub_key_len,
				const uint8_t *digest, size_t digest_len,
				const uint8_t *signature, size_t signature_len);

/**
 * @brief Verify a RSA signature using a public key in the OPTIGA
 *
 * @param ctx Command context to use
 * @param oid Object ID of the public key to use
 * @param digest Digest to verify the signature of
 * @param digest_len Length of digest
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return 0 if the signature matches, error code otherwise
 */
int optrust_rsa_verify_oid(struct optrust_ctx *ctx, uint16_t oid, enum OPTRUST_SIGNATURE_SCHEME scheme,
				const uint8_t *digest, size_t digest_len, const uint8_t *signature, size_t signature_len);

/**
 * @brief Derive a key from a shared secret
 *
 * @param ctx Command context to use
 * @param sec_oid Object ID of the shared secret to use
 * @param deriv_data Secret derivation data
 * @param deriv_data_len Length of deriv_data
 * @param key_len Length of the key to derive
 * @param key_oid OID to store the derived key
 * @return 0 if the signature matches, error code otherwise
 */
int optrust_tls1_2_prf_sha256_calc_oid(struct optrust_ctx *ctx, uint16_t sec_oid, const uint8_t *deriv_data, size_t deriv_data_len,
				size_t key_len, uint16_t key_oid);

/**
 * @brief Derive a key from a shared secret and export the key
 *
 * @param ctx Command context to use
 * @param sec_oid Object ID of the shared secret to use
 * @param deriv_data Secret derivation data
 * @param deriv_data_len Length of deriv_data
 * @param key Output buffer for the derived key
 * @param key_len Length of deriv and length of the secret to derive
 * @return 0 if the signature matches, error code otherwise
 */
int optrust_tls1_2_prf_sha256_calc_ext(struct optrust_ctx *ctx, uint16_t sec_oid, const uint8_t *deriv_data, size_t deriv_data_len,
				uint8_t *key, size_t key_len);

/**
 * @brief Encrypt data using a public RSA key
 *
 * @param ctx Command context to use
 * @param msg Message to encrypt
 * @param msg_len Length of msg
 * @param alg Algorithm of the public key
 * @param pub_key Public key to use for encryption
 * @param pub_key_len Length of pub_key
 * @param enc_msg Output buffer for the encrypted message
 * @param enc_msg_len Length of enc_msg, contains written bytes afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_rsa_encrypt_msg_ext(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				enum OPTRUST_ALGORITHM alg, const uint8_t *pub_key, size_t pub_key_len,
				uint8_t *enc_msg, size_t *enc_msg_len);

/**
 * @brief Encrypt data in an OID using a public RSA public key
 *
 * @param ctx Command context to use
 * @param oid OID of which the data should be encrypted
 * @param alg Algorithm of the public key
 * @param pub_key Public key to use for encryption
 * @param pub_key_len Length of pub_key
 * @param enc_msg Output buffer for the encrypted message
 * @param enc_msg_len Length of enc_msg, contains written bytes afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_rsa_encrypt_oid_ext(struct optrust_ctx *ctx, uint16_t oid,
				enum OPTRUST_ALGORITHM alg, const uint8_t *pub_key, size_t pub_key_len,
				uint8_t *enc_msg, size_t *enc_msg_len);

/**
 * @brief Encrypt data using a RSA Public Key Certificate from the device
 *
 * @param ctx Command context to use
 * @param msg Message to encrypt
 * @param msg_len Length of msg
 * @param alg Algorithm of the public key
 * @param pub_key Public key to use for encryption
 * @param pub_key_len Length of pub_key
 * @param enc_msg Output buffer for the encrypted message
 * @param enc_msg_len Length of enc_msg, contains written bytes afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_rsa_encrypt_msg_oid(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				uint16_t cert_oid,	uint8_t *enc_msg, size_t *enc_msg_len);

/**
 * @brief Encrypt data in an OID using a RSA Public Key Certificate from the device
 *
 * @param ctx Command context to use
 * @param msg_oid OID of which the data should be encrypted
 * @param alg Algorithm of the public key
 * @param pub_key Public key to use for encryption
 * @param pub_key_len Length of pub_key
 * @param enc_msg Output buffer for the encrypted message
 * @param enc_msg_len Length of enc_msg, contains written bytes afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_rsa_encrypt_oid_oid(struct optrust_ctx *ctx, uint16_t msg_oid,
				uint16_t cert_oid,	uint8_t *enc_msg, size_t *enc_msg_len);

/**
 * @brief Decrypt a message using a RSA private key from the device
 *
 * @param ctx Command context to use
 * @param msg Message to decrypt
 * @param msg_len Length of msg
 * @param key_oid OID of the decryption key
 * @param enc_msg Output buffer for the encrypted message
 * @param enc_msg_len Length of enc_msg, contains written bytes afterwards
 * @return 0 on success, error code otherwise
 */
int optrust_rsa_decrypt_msg_oid(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				uint16_t key_oid,	uint8_t *dec_msg, size_t *dec_msg_len);

/**
 * @brief Decrypt a message using a RSA private key from the device and store it in an OID
 *
 * @param ctx Command context to use
 * @param msg Message to decrypt
 * @param msg_len Length of msg
 * @param key_oid OID of the decryption key
 * @param dec_oid OID to store the decrypted message
 * @return 0 on success, error code otherwise
 */
int optrust_rsa_decrypt_oid_oid(struct optrust_ctx *ctx, const uint8_t *msg, size_t msg_len,
				uint16_t key_oid,	uint16_t dec_oid);

#endif /* ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_TRUST_M_H_ */
