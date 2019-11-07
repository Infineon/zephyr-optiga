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

	const u8_t optiga_open_application_apdu[] =
	{
		0xF0, /* command code */
		0x00, /* clean context */
		0x00, 0x10, /* 16 bytes parameter */
		/* unique application identifier */
		0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C,
	};

	res = optiga_nettran_send_apdu(dev, optiga_open_application_apdu, sizeof(optiga_open_application_apdu));

	LOG_INF("APDU send result: %d", res);
	k_sleep(500);

	res = optiga_reg_read(dev, 0x82, status_reg, 4);

	if (res != 0) {
		LOG_INF("Failed to read status register");
		return;
	}

	LOG_HEXDUMP_INF(status_reg, 4, "Read status register:");

	u8_t tmp_buf[100] = {0};
	size_t tmp_buf_len = 100;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to read APDU response");
		return;
	}

	LOG_HEXDUMP_INF(tmp_buf, tmp_buf_len, "Open Application response:");

	return;

	while(true) {
		res = optiga_reg_read(dev, 0x82, status_reg, 4);

		if (res != 0) {
			LOG_INF("Failed to read status register");
			return;
		}

		LOG_HEXDUMP_INF(status_reg, 4, "Read status register:");
		k_sleep(500);
	}



	u8_t data_reg_len_reg[2] = {0};
	res = optiga_reg_read(dev, 0x81, data_reg_len_reg, 2);
	if (res != 0) {
		LOG_INF("Failed to read data reg len register");
		return;
	}

	LOG_HEXDUMP_INF(data_reg_len_reg, 2, "Read data reg len:");

	// set to 0x0040
	data_reg_len_reg[0] = 0;
	data_reg_len_reg[1] = 0x40;

	res = optiga_reg_write(dev, 0x81, data_reg_len_reg, 2);
	if (res != 0) {
		LOG_INF("Failed to write data reg len register");
		return;
	}

	memset(data_reg_len_reg, 0, 2);

	res = optiga_reg_read(dev, 0x81, data_reg_len_reg, 2);
	if (res != 0) {
		LOG_INF("Failed to read data reg len register");
		return;
	}

	LOG_HEXDUMP_INF(data_reg_len_reg, 2, "Read data reg len:");

	/* reset and check data_reg_len if it worked */
	res =  optiga_soft_reset(dev);
	if (res != 0) {
		LOG_INF("Failed to perform soft reset");
		return;
	}

	memset(data_reg_len_reg, 0, 2);

	res = optiga_reg_read(dev, 0x81, data_reg_len_reg, 2);
	if (res != 0) {
		LOG_INF("Failed to read data reg len register");
		return;
	}

	LOG_HEXDUMP_INF(data_reg_len_reg, 2, "Read data reg len:");

	/* Test case for FCS */
	u8_t fcs_test_vec[] = {0xa0, 0x00, 0x00};
	u8_t fcs_test_res[] = {0x0f, 0xd7};
	u8_t fcs_test_vec2[] = {0xa0, 0x00, 0x00, 0x00, 0x00};
	optiga_data_frame_set_fcs(fcs_test_vec2, 3);
	/* End test case for FCS */
}
