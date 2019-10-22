/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_

struct optiga_data {
	struct device *i2c_master;
};

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_ */