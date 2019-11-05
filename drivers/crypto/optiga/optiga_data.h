/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_

#include <zephyr.h>
#include <kernel.h>
#include <drivers/i2c.h>

// TODO: make configurable via Kconfig
// This is a device limit, currently from the OPTIGA Trust X datasheet
#define MAX_PACKET_SIZE 0x110


/*
 * 1 byte  FCTR
 * 2 bytes LEN
 * 2 bytes FCS
 */
#define DATA_LINK_OVERHEAD 5

struct data_link_layer {
	size_t frame_len;
	u8_t frame_buf[MAX_PACKET_SIZE + DATA_LINK_OVERHEAD];
	u8_t frame_nr;
	u8_t frame_ack;
	u8_t retry_cnt;
};

int optiga_data_init(struct device *dev);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_ */