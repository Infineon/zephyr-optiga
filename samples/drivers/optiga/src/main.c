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
#include "cmds_trust_x.h"

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(main);
struct device *dev = NULL;

#define TMP_BUF_SIZE 1024
static u8_t tmp_buf[TMP_BUF_SIZE] = {0};
static size_t tmp_buf_len = TMP_BUF_SIZE;

// compares if two buffers have the same length and matching content
int equals(const void * buf1, size_t len1, const void * buf2, size_t len2)
{
	if((len1 == len2) && (memcmp(buf1, buf2, len1) == 0)) {
		return 1;
	}

	return 0;
}

void read_status()
{
	u8_t status_reg[4] = {0};
	int res = optiga_reg_read(dev, 0x82, status_reg, 4);

	if (res != 0) {
		LOG_INF("Failed to read status register");
		return;
	}

	LOG_HEXDUMP_INF(status_reg, 4, "Read status register:");
}

void test_fcs()
{
	/* Test case for FCS */
	const u8_t fcs_test_vec[] = {0xa0, 0x00, 0x00};
	const u8_t fcs_test_res[] = {0x0f, 0xd7};
	u8_t fcs_test_vec2[] = {0xa0, 0x00, 0x00, 0x00, 0x00};
	optiga_data_frame_set_fcs(fcs_test_vec2, 3);
	assert(fcs_test_vec2[3] == fcs_test_res[0]);
	assert(fcs_test_vec2[4] == fcs_test_res[1]);
}

void set_data_object()
{
	const u8_t set_data_object_apdu[] = {
		0x82, /* command code */
		0x40, /* param, erease & write data */
		0x02, 0x04, /* Length */
		0xF1, 0xE0, /* OID */
		0x00, 0x00, /* Offset */
		0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xEF, /* 16 bytes data */
														/* 512 bytes total */
		};

	LOG_INF("Set DO:");
	int res = optiga_nettran_send_apdu(dev,
		set_data_object_apdu,
		sizeof(set_data_object_apdu));

	LOG_INF("APDU send result: %d", res);

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to read set DO APDU response");
		return;
	}

	LOG_HEXDUMP_INF(tmp_buf, tmp_buf_len, "Set DO response:");
}

void get_data_object_small()
{
	const u8_t get_data_object_apdu[] = {
		0x81, /* command code */
		0x00, /* param, read data */
		0x00, 0x06, /* Length */
		0xF1, 0xE0, /* OID */
		0x00, 0x00, /* Offset */
		0x00, 0x10,
	};

	LOG_INF("Get DO:");
	int res = optiga_nettran_send_apdu(dev,
		get_data_object_apdu,
		sizeof(get_data_object_apdu));

	LOG_INF("APDU send result: %d", res);
	k_sleep(500);

	read_status();

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to read get DO APDU response");
		return;
	}

	LOG_HEXDUMP_INF(tmp_buf, tmp_buf_len, "Get DO response:");
}

void get_data_object()
{
	const u8_t get_data_object_apdu[] = {
		0x81, /* command code */
		0x00, /* param, read data */
		0x00, 0x02, /* Length */
		0xF1, 0xE0, /* OID */
	};

	LOG_INF("Get DO:");
	int res = optiga_nettran_send_apdu(dev,
		get_data_object_apdu,
		sizeof(get_data_object_apdu));

	LOG_INF("APDU send result: %d", res);

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to read get DO APDU response");
		return;
	}

	LOG_HEXDUMP_INF(tmp_buf, tmp_buf_len, "Get DO response:");
}

void get_data_object_queued()
{
	const u8_t get_data_object_apdu[] = {
		0x81, /* command code */
		0x00, /* param, read data */
		0x00, 0x02, /* Length */
		0xF1, 0xE0, /* OID */
	};

	LOG_INF("Get DO:");

	struct optiga_apdu get_do_txrx = {
		.tx_buf = get_data_object_apdu,
		.tx_len = sizeof(get_data_object_apdu),
		.rx_buf = tmp_buf,
		.rx_len = TMP_BUF_SIZE,
	};

	optiga_enqueue_apdu(dev, &get_do_txrx);

	struct k_poll_event events[1] = {
        K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL,
                                 K_POLL_MODE_NOTIFY_ONLY,
                                 &get_do_txrx.finished),
	};

	k_poll(events, 1, K_FOREVER);

	if(get_do_txrx.status_code != 0x00) {
		LOG_INF("Error Code: 0x%02x", get_do_txrx.status_code);
		return;
	}

	LOG_HEXDUMP_INF(tmp_buf, get_do_txrx.rx_len, "Get DO response:");
}

void set_data_object_small()
{
	const u8_t set_data_object_apdu[] = {
		0x82, /* command code */
		0x40, /* param, erease & write data */
		0x00, 20, /* Length */
		0xF1, 0xE0, /* OID */
		0x00, 0x00, /* Offset */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		};

	LOG_INF("Set DO:");
	int res = optiga_nettran_send_apdu(dev,
		set_data_object_apdu,
		sizeof(set_data_object_apdu));

	LOG_INF("APDU send result: %d", res);

	read_status();

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to read set DO APDU response");
		return;
	}

	LOG_HEXDUMP_INF(tmp_buf, tmp_buf_len, "Set DO response:");
}

void phy_test()
{
	u8_t data_reg_len_reg[2] = {0};
	int res = optiga_reg_read(dev, 0x81, data_reg_len_reg, 2);
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
}

void main(void)
{
	LOG_INF("Hello OPTIGA");
	dev = device_get_binding("trust-m");

	if (dev == NULL) {
		LOG_INF("Could not get Trust M device\n");
		return;
	}

	LOG_INF("Found Trust M device");

	test_fcs();
	//read_status();
	//set_data_object();
	//k_sleep(100);
	//get_data_object_queued();
	//read_status();

	struct cmds_ctx ctx;

	int res = cmds_trust_x_init(&ctx, dev, tmp_buf, TMP_BUF_SIZE);

	LOG_INF("cmds_trust_x_init res: %d", res);

	u8_t res_buf[400] = {0};
	size_t res_len = 400;

	res = cmds_trust_x_get_data_object(&ctx, 0xF1E0, 0, res_buf, &res_len);

	LOG_INF("cmds_trust_x_get_data_object res: %d", res);
	LOG_HEXDUMP_INF(res_buf, res_len, "Get DO:");

	/* Flip some bits */
	res_buf[0] ^= 0x0F;
	k_sleep(100);

	res = cmds_trust_x_set_data_object(&ctx, 0xF1E0, 0, res_buf, res_len);
	LOG_INF("cmds_trust_x_set_data_object res: %d", res);
	k_sleep(100);

	res = cmds_trust_x_get_data_object(&ctx, 0xF1E0, 0, res_buf, &res_len);

	LOG_INF("cmds_trust_x_get_data_object res: %d", res);
	LOG_HEXDUMP_INF(res_buf, res_len, "Get DO:");


	while(true) {
		read_status();
		k_sleep(1000);
	}


}