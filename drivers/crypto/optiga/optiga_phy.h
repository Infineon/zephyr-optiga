/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PHY_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PHY_H_

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
#define DL_OVERHEAD 5

// This are the protocol limits from Table 2-1
#define OPTIGA_DATA_REG_LEN_MAX 0xFFFF
#define OPTIGA_DATA_REG_LEN_MIN 0x10

#define DATA_REG_LEN (MAX_PACKET_SIZE + 5)

#if DATA_REG_LEN < OPTIGA_DATA_REG_LEN_MIN || DATA_REG_LEN > OPTIGA_DATA_REG_LEN_MAX
#error "DATA_REG_LEN outside protocol limits"
#endif

/* 1 byte for register address on writes */
#define PHY_OVERHEAD 1

#define REG_WRITE_BUF_SIZE (DATA_REG_LEN + PHY_OVERHEAD)

struct physical_layer {
	u16_t data_reg_len;
	u8_t reg_write_buf[REG_WRITE_BUF_SIZE];
};

int optiga_reg_read(struct device *dev, u8_t addr, u8_t *data, size_t len);
int optiga_reg_write(struct device *dev, u8_t addr, const u8_t *data, size_t len);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_PHY_H_ */