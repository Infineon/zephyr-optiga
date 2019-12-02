/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_

#include "optiga_phy.h"
#include "optiga_data.h"
#include "optiga_nettran.h"

struct optiga_data {
	struct device *i2c_master;
	struct physical_layer phy;
	struct data_link_layer data;
	struct nettran_layer nettran;
	struct k_fifo apdu_queue;
	struct k_thread worker;
	k_thread_stack_t *worker_stack;
};

struct optiga_cfg {
	char *i2c_dev_name;
	u16_t i2c_addr;
};

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_CRYPTO_OPTIGA_H_ */