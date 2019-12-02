/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public API for display drivers and applications
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_H_
#define ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_H_

#include <device.h>
#include <zephyr/types.h>

struct optiga_apdu {
	void *fifo_reserved;   /* 1st word reserved for use by fifo */
	const u8_t *tx_buf;
	size_t tx_len;
	u8_t *rx_buf;
	size_t rx_len;
	u8_t status_code;
	struct k_poll_signal finished;
};

typedef int (*optiga_enqueue_apdu_t)(struct device *dev, struct optiga_apdu *apdu);

struct optiga_api {
	optiga_enqueue_apdu_t optiga_enqueue_apdu;
};

__syscall int optiga_enqueue_apdu(struct device *dev, struct optiga_apdu *apdu);

static inline int z_impl_optiga_enqueue_apdu(struct device *dev, struct optiga_apdu *apdu)
{
	const struct optiga_api *api = dev->driver_api;

	return api->optiga_enqueue_apdu(dev, apdu);
}

#include <syscalls/optiga.h>

#endif /* ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_H_ */
