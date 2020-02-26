/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_

#include "optiga_phy.h"
#include "optiga_data.h"
#include "optiga_nettran.h"

#include <drivers/gpio.h>

struct optiga_data {
	struct device *i2c_master;
	struct device *gpio;
	struct physical_layer phy;
	struct data_link_layer data;
	struct nettran_layer nettran;
	struct k_fifo apdu_queue;
	struct k_thread worker;
	k_thread_stack_t *worker_stack;
	int reset_counter;
	bool open;

};

struct optiga_cfg {
	const char *i2c_dev_name;
	const char *power_label;
	u16_t i2c_addr;
	gpio_pin_t power_pin;
	gpio_dt_flags_t power_flags;
};

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_ */