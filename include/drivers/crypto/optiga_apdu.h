/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public API for OPTIGA devices at APDU level
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_APDU_H_
#define ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_APDU_H_

#include <device.h>
#include <zephyr/types.h>

#define OPTIGA_STATUS_CODE_SUCCESS 0
#define OPTIGA_MAX_SESSION_IDX 31

/* Sessions numbers lower than this number are ignored when going to hibernate */
#define OPTIGA_WAKE_LOCK_IGNORED_SESSIONS 8

struct optiga_apdu {
	void *fifo_reserved;   /* 1st word reserved for use by fifo */
	const uint8_t *tx_buf;
	size_t tx_len;
	uint8_t *rx_buf;
	size_t rx_len;
	struct k_poll_signal finished;
};

typedef int (*optiga_enqueue_apdu_t)(struct device *dev, struct optiga_apdu *apdu);
typedef bool (*optiga_session_acquire_t)(struct device *dev, int session_idx);
typedef void (*optiga_session_release_t)(struct device *dev, int session_idx);
typedef int (*optiga_start_shield_t)(struct device *dev, const uint8_t *key, size_t key_len);

struct optiga_api {
	optiga_enqueue_apdu_t optiga_enqueue_apdu;
	optiga_session_acquire_t optiga_session_acquire;
	optiga_session_release_t optiga_session_release;
	optiga_start_shield_t optiga_start_shield;
};

__syscall int optiga_enqueue_apdu(struct device *dev, struct optiga_apdu *apdu);

static inline int z_impl_optiga_enqueue_apdu(struct device *dev, struct optiga_apdu *apdu)
{
	const struct optiga_api *api = dev->driver_api;

	return api->optiga_enqueue_apdu(dev, apdu);
}

static inline bool optiga_is_driver_error(int error_code)
{
	return error_code < OPTIGA_STATUS_CODE_SUCCESS;
}

static inline bool optiga_is_device_error(int error_code)
{
	return error_code > OPTIGA_STATUS_CODE_SUCCESS;
}

/* Acquire a token that locks a session context. It must be returned via optiga_session_release.
 * Returns false if the requested token is not available
 */
__syscall bool optiga_session_acquire(struct device *dev, int session_idx);

static inline bool z_impl_optiga_session_acquire(struct device *dev, int session_idx)
{
	const struct optiga_api *api = dev->driver_api;

	return api->optiga_session_acquire(dev, session_idx);
}

__syscall void optiga_session_release(struct device *dev, int session_idx);

static inline void z_impl_optiga_session_release(struct device *dev, int session_idx)
{
	const struct optiga_api *api = dev->driver_api;

	return api->optiga_session_release(dev, session_idx);
}

__syscall int optiga_start_shield(struct device *dev, const uint8_t *key, size_t key_len);

static inline int z_impl_optiga_start_shield(struct device *dev, const uint8_t *key, size_t key_len)
{
	const struct optiga_api *api = dev->driver_api;

	return api->optiga_start_shield(dev, key, key_len);
}

#include <syscalls/optiga_apdu.h>

#endif /* ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_APDU_H_ */
