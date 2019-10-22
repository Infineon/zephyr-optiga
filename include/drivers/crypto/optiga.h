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

int optiga_reg_read(struct device *dev, u8_t addr, u8_t *data, size_t len);
int optiga_reg_write(struct device *dev, u8_t addr, const u8_t *data, size_t len);

#endif /* ZEPHYR_INCLUDE_DRIVERS_CRYPTO_OPTIGA_H_ */
