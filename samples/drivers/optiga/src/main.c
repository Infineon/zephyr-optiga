/*
 * Copyright (c) 2018 Savoir-Faire Linux.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <device.h>
#include <errno.h>
#include <drivers/crypto/optiga.h>
#include <sys/util.h>
#include <zephyr.h>

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);

void main(void)
{
	LOG_INF("Hello OPTIGA");
	struct device *dev = device_get_binding("trust-m");

	if (dev == NULL) {
		LOG_INF("Could not get Trust M device\n");
		return;
	}

	LOG_INF("Found Trust M device\n");

	u8_t status_reg[4] = {0};
	int res = optiga_reg_read(dev, 0x82, status_reg, 4);

	if (res != 0) {
		LOG_INF("Failed to read status register");
		return;
	}

	LOG_HEXDUMP_INF(status_reg, 4, "Read status register:");
}
