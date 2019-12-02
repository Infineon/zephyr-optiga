/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <drivers/gpio.h>
#include <drivers/i2c.h>
#include <kernel.h>
#include <zephyr.h>

#include "crypto_optiga.h"
#include "optiga_phy.h"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga);

typedef int (*dummy_api_t)();

struct dummy_api {
	dummy_api_t dummy;
};

static const struct dummy_api dummy_funcs = {
	.dummy = NULL,
};

#define OPTIGA_OID_ERROR_CODE 0xF1C2

static const u8_t error_code_apdu[] =
{
	0x01, /* get DataObject, don't clear error code because we want to read it */
	0x00, /* read data */
	0x00, 0x06, /* 6 bytes following */
	0xF1, 0xC2, /* Error codes object */
	0x00, 0x00, /* Offset */
	0x00, 0x01, /* all error codes are 1 byte */
};

/*
 * Initializes the application on the OPTIGA chip
 */
static int optiga_open_application(struct device *dev)
{
	static const u8_t optiga_open_application_apdu[] =
	{
		0xF0, /* command code */
		0x00, /* clean context */
		0x00, 0x10, /* 16 bytes parameter */
		/* unique application identifier */
		0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C,
	};

	int res = optiga_nettran_send_apdu(dev,
		optiga_open_application_apdu,
		sizeof(optiga_open_application_apdu));
	if(res != 0) {
		LOG_ERR("Failed to send OpenApplication APDU");
		return res;
	}

	// TODO: reduce buffer size once the communication stack overhead has been eliminated
	u8_t tmp_buf[16] = {0};
	size_t tmp_buf_len = 16;

	/* Expected response to "OpenApplication" */
	const u8_t resp[4] = {0};
	const size_t resp_len = 4;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to OpenApplication APDU response");
		return res;
	}

	if(resp_len != tmp_buf_len || memcmp(tmp_buf, resp, resp_len)) {
		LOG_HEXDUMP_ERR(tmp_buf, tmp_buf_len, "Unexpected response: ");
		return -EIO;
	}

	return 0;
}

int optiga_get_error_code(struct device *dev, u8_t *err_code)
{
	__ASSERT(dev, "Invalid NULL pointer");
	__ASSERT(err_code, "Invalid NULL pointer");

	int res = optiga_nettran_send_apdu(dev,
		error_code_apdu,
		sizeof(error_code_apdu));
	if(res != 0) {
		LOG_ERR("Failed to send Error Code APDU");
		return res;
	}

	// TODO: reduce buffer size once the communication stack overhead has been eliminated
	u8_t tmp_buf[16] = {0};
	size_t tmp_buf_len = 16;


	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to get Error Code APDU response");
		return res;
	}

	/* Expected APDU return length is always 5 */
	if (tmp_buf_len != 5) {
		LOG_ERR("Unexpected response length");
		return -EIO;
	}

	if (tmp_buf[0] != 0) {
		LOG_ERR("Failed to retrieve Error Code");
		return -EIO;
	}

	if (tmp_buf[2] != 0x00 || tmp_buf[3] != 0x01) {
		LOG_ERR("Unexpected data length");
		return -EIO;
	}

	*err_code = tmp_buf[4];

	return 0;
}

int optiga_init(struct device *dev)
{
	LOG_DBG("Init OPTIGA");

	const struct optiga_cfg *config = dev->config->config_info;
	struct optiga_data *data = dev->driver_data;

	data->i2c_master = device_get_binding(config->i2c_dev_name);
	if (data->i2c_master == NULL) {
		LOG_ERR("Failed to get I2C device");
		return -EINVAL;
	}

	int err = optiga_phy_init(dev);
	if(err != 0) {
		LOG_ERR("Failed to initialise OPTIGA phy layer");
		return err;
	}

	err = optiga_data_init(dev);
	if(err != 0) {
		LOG_ERR("Failed to initialise OPTIGA data link layer");
		return err;
	}

	err = optiga_nettran_init(dev);
	if(err != 0) {
		LOG_ERR("Failed to initialise OPTIGA nettran layer");
		return err;
	}

	err = optiga_open_application(dev);
	if(err != 0) {
		LOG_ERR("Failed to open the OPTIGA application");
		return err;
	}

	return 0;
}

#define OPTIGA_DEVICE(id)						\
	static const struct optiga_cfg optiga_##id##_cfg = {		\
		.i2c_dev_name = DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_BUS_NAME,	\
		.i2c_addr     = DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_BASE_ADDRESS,	\
	};								\
									\
static struct optiga_data optiga_##id##_data;				\
									\
DEVICE_AND_API_INIT(optiga_##id, DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_LABEL,	\
		    &optiga_init, &optiga_##id##_data,		\
		    &optiga_##id##_cfg, POST_KERNEL,			\
		    CONFIG_CRYPTO_INIT_PRIORITY, &dummy_funcs)

#ifdef DT_INST_0_INFINEON_OPTIGA_TRUST_M
OPTIGA_DEVICE(0);
#endif /* DT_INST_0_INFINEON_OPTIGA_TRUST_M */