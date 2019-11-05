/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_NETTRAN_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_NETTRAN_H_

#include <zephyr.h>
#include <kernel.h>
#include <drivers/i2c.h>

// TODO: make configurable via Kconfig
// This is a device limit, currently from the OPTIGA Trust X datasheet
#define MAX_PACKET_SIZE 0x110

/* PCTR header */
#define OPTIGA_NETTRAN_OVERHEAD 1

/* network and transport */
struct nettran_layer {
	u8_t packet_buf[MAX_PACKET_SIZE + OPTIGA_NETTRAN_OVERHEAD];
};

int optiga_nettran_send_apdu(struct device *dev, const u8_t *data, size_t len);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_NETTRAN_H_ */