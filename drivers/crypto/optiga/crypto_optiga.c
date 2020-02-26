/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <drivers/gpio.h>
#include <drivers/i2c.h>
#include <kernel.h>
#include <zephyr.h>
#include <drivers/crypto/optiga.h>

#include "crypto_optiga.h"
#include "optiga_phy.h"

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga);

#define OPTIGA_STACK_SIZE (1024)
// TODO(chr): make Kconfig tunable
#define OPTIGA_THREAD_PRIORITY 1
#define OPTIGA_MAX_RESET 3
#define OPTIGA_HIBERNATE_DELAY_MS 500

static void optiga_worker(void* arg1, void *arg2, void *arg3);

#define OPTIGA_GET_ERROR_RESPONSE_LEN 5
/* GetDataObject command with a special data object storing the error code */
static const u8_t error_code_apdu[] =
{
	0x01, /* get DataObject, don't clear error code because we want to read it */
	0x00, /* read data */
	0x00, 0x06, /* 6 bytes following */
	0xF1, 0xC2, /* Error codes object */
	0x00, 0x00, /* Offset */
	0x00, 0x01, /* all error codes are 1 byte */
};

#define OPTIGA_APDU_STA_OFFSET 0
#define OPTIGA_APDU_STA_SUCCESS 0
#define OPTIGA_APDU_OUT_DATA_OFFSET 4

#define OPTIGA_OPEN_APPLICATION_RESPONSE_LEN 4

#define OPTIGA_OPEN_APPLICATION_LEN 20
#define OPTIGA_RESTORE_APPLICATION_LEN 28
#define OPTIGA_PARAM_OFFS 1
#define OPTIGA_CTX_HANDLE_LEN 8

static const u8_t optiga_open_application_apdu[OPTIGA_OPEN_APPLICATION_LEN] =
{
	0xF0, /* command code */
	0x00, /* Param */
	0x00, 0x10, /* 16 bytes parameter */
	/* unique application identifier */
	0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C,
};

/*
 * Initializes the application on the OPTIGA chip
 */
static int optiga_open_application(struct device *dev, const u8_t *handle)
{
	u8_t tmp_buf[OPTIGA_RESTORE_APPLICATION_LEN] = {0};
	size_t tmp_buf_len = 0;
	struct optiga_data *data = dev->driver_data;
	/* on all error paths the application is not opened */
	data->open = false;

	memcpy(tmp_buf, optiga_open_application_apdu, OPTIGA_OPEN_APPLICATION_LEN);

	if (handle == NULL) {
		tmp_buf_len = OPTIGA_OPEN_APPLICATION_LEN;
	} else {
		tmp_buf[OPTIGA_PARAM_OFFS] = 0x01; // TODO(chr): extract constant
		memcpy(tmp_buf + OPTIGA_OPEN_APPLICATION_LEN, handle, OPTIGA_CTX_HANDLE_LEN);
		tmp_buf_len = OPTIGA_RESTORE_APPLICATION_LEN;
	}

	int err = optiga_nettran_send_apdu(dev,	tmp_buf, tmp_buf_len);
	if (err != 0) {
		LOG_ERR("Failed to send OpenApplication APDU");
		return err;
	}

	/* Expected response to "OpenApplication" */
	static const u8_t resp[OPTIGA_OPEN_APPLICATION_RESPONSE_LEN] = {0};
	static const size_t resp_len = OPTIGA_OPEN_APPLICATION_RESPONSE_LEN;

	tmp_buf_len = OPTIGA_RESTORE_APPLICATION_LEN;
	err = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (err != 0) {
		LOG_INF("Failed to get OpenApplication APDU response");
		return err;
	}

	if(resp_len != tmp_buf_len || memcmp(tmp_buf, resp, resp_len)) {
		LOG_HEXDUMP_ERR(tmp_buf, tmp_buf_len, "Unexpected response: ");
		return -EIO;
	}

	data->open = true;
	return 0;
}

#define OPTIGA_CLOSE_APPLICATION_LEN 4

static const u8_t optiga_close_application_apdu[OPTIGA_CLOSE_APPLICATION_LEN] =
{
	0xF1, /* command code */
	0x00, /* Param */
	0x00, 0x00, /* No InData */
};

static int optiga_close_application(struct device *dev, u8_t *handle)
{
	u8_t tmp_buf[OPTIGA_CTX_HANDLE_LEN] = {0};
	size_t tmp_buf_len = 0;
	struct optiga_data *data = dev->driver_data;

	memcpy(tmp_buf, optiga_close_application_apdu, OPTIGA_CLOSE_APPLICATION_LEN);
	tmp_buf_len = OPTIGA_CLOSE_APPLICATION_LEN;

	if (handle != NULL) {
		tmp_buf[OPTIGA_PARAM_OFFS] = 0x01; // TODO(chr): extract constant
	}

	int err = optiga_nettran_send_apdu(dev,	tmp_buf, tmp_buf_len);
	if(err != 0) {
		LOG_ERR("Failed to send OpenApplication APDU");
		return err;
	}

	tmp_buf_len = OPTIGA_CTX_HANDLE_LEN;
	err = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (err != 0) {
		LOG_INF("Failed to get OpenApplication APDU response");
		return err;
	}

	if (handle != NULL) {
		if (tmp_buf_len != (OPTIGA_CTX_HANDLE_LEN + OPTIGA_APDU_OUT_DATA_OFFSET)
			|| tmp_buf[OPTIGA_APDU_STA_OFFSET] != OPTIGA_APDU_STA_SUCCESS)
		{
			LOG_HEXDUMP_ERR(tmp_buf, tmp_buf_len, "Unexpected response: ");
			return -EIO;
		}

		memcpy(handle, tmp_buf + OPTIGA_APDU_OUT_DATA_OFFSET, OPTIGA_CTX_HANDLE_LEN);
	} else {
		if (tmp_buf_len != 4 ||  tmp_buf[OPTIGA_APDU_STA_OFFSET] != OPTIGA_APDU_STA_SUCCESS) {
			LOG_HEXDUMP_ERR(tmp_buf, tmp_buf_len, "Unexpected response: ");
			return -EIO;
		}
	}

	data->open = false;
	return 0;
}

int optiga_get_error_code(struct device *dev, u8_t *err_code)
{
	__ASSERT(dev, "Invalid NULL pointer");
	__ASSERT(err_code, "Invalid NULL pointer");

	int err = optiga_nettran_send_apdu(dev,
		error_code_apdu,
		sizeof(error_code_apdu));
	if(err != 0) {
		LOG_ERR("Failed to send Error Code APDU");
		return err;
	}

	u8_t tmp_buf[OPTIGA_GET_ERROR_RESPONSE_LEN] = {0};
	size_t tmp_buf_len = OPTIGA_GET_ERROR_RESPONSE_LEN;


	err = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (err != 0) {
		LOG_INF("Failed to get Error Code APDU response");
		return err;
	}

	/* Expected APDU return length is always 5 */
	if (tmp_buf_len != OPTIGA_GET_ERROR_RESPONSE_LEN) {
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

/* From Trust M datasheet, table 11 */
#define OPTIGA_STARTUP_TIME_MS 15

static int optiga_power(struct device *dev, bool enable)
{
	const struct optiga_cfg *config = dev->config->config_info;
	struct optiga_data *data = dev->driver_data;
	int ret = gpio_pin_set(data->gpio, config->power_pin, enable);

	if(ret != 0) {
		return ret;
	}

	/* Wait for OPTIGA to start when turning on */
	if (enable) {
		k_sleep(OPTIGA_STARTUP_TIME_MS);
	}

	return 0;
}

int optiga_reset(struct device *dev)
{
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

	err = optiga_open_application(dev, NULL);
	if(err != 0) {
		LOG_ERR("Failed to open the OPTIGA application");
		return err;
	}

	return err;
}

int optiga_init(struct device *dev)
{
	LOG_DBG("Init OPTIGA");

	const struct optiga_cfg *config = dev->config->config_info;
	struct optiga_data *data = dev->driver_data;

	data->gpio = device_get_binding(config->power_label);
	if (data->gpio == NULL) {
		LOG_ERR("Failed to get GPIO device");
		return -EINVAL;
	}

	/* Initialize power pin */
	gpio_pin_configure(data->gpio, config->power_pin,
			   GPIO_OUTPUT | config->power_flags);

	/* Power on OPTIGA */
	optiga_power(dev, true);

	data->reset_counter = 0;
	data->i2c_master = device_get_binding(config->i2c_dev_name);
	if (data->i2c_master == NULL) {
		LOG_ERR("Failed to get I2C device");
		return -EINVAL;
	}

	int err = optiga_reset(dev);
	if(err != 0) {
		return err;
	}

	k_fifo_init(&data->apdu_queue);

	k_thread_create(&data->worker, data->worker_stack,
			 OPTIGA_STACK_SIZE,
			 optiga_worker,
			 dev, NULL, NULL,
			 OPTIGA_THREAD_PRIORITY, 0, K_NO_WAIT);

	return 0;
}

static int enqueue_apdu(struct device *dev, struct optiga_apdu *apdu)
{
	__ASSERT(dev, "Invalid NULL pointer");
	__ASSERT(apdu, "Invalid NULL pointer");
	k_poll_signal_init(&apdu->finished);
	struct optiga_data *data = dev->driver_data;

	k_fifo_put(&data->apdu_queue, apdu);
	return 0;
}

static int optiga_transfer_apdu(struct device *dev, struct optiga_apdu *apdu)
{
	int err = optiga_nettran_send_apdu(dev,	apdu->tx_buf, apdu->tx_len);
	if(err != 0) {
		LOG_ERR("Failed to send APDU");
		return err;
	}

	err = optiga_nettran_recv_apdu(dev, apdu->rx_buf, &apdu->rx_len);
	if (err != 0) {
		LOG_ERR("Failed to receive APDU");
		return err;
	}

	return err;
}

static bool optiga_apdu_is_error(u8_t *apdu_start)
{
	return apdu_start[OPTIGA_APDU_STA_OFFSET] != OPTIGA_APDU_STA_SUCCESS;
}

static void optiga_worker(void* arg1, void *arg2, void *arg3)
{
	struct device *dev = arg1;
	struct optiga_data *data = dev->driver_data;

	/* execute forevever */
	while (true) {
		struct optiga_apdu *apdu = NULL;
		if (data->open) {
			apdu = k_fifo_get(&data->apdu_queue, OPTIGA_HIBERNATE_DELAY_MS);
			if (apdu == NULL) {
				// TODO(chr): distinguish between Trust X and M, save handle if needed
				optiga_close_application(dev, NULL);
				optiga_power(dev, false);
				continue;
			}
		} else {
			apdu = k_fifo_get(&data->apdu_queue, K_FOREVER);
			// TODO(chr): distinguish between Trust X and M
			optiga_power(dev, true);
			//optiga_open_application(dev, NULL);
			optiga_reset(dev);
		}

		if (data->reset_counter > OPTIGA_MAX_RESET) {
			/* Return an error for all further requests */
			LOG_ERR("Maximum OPTIGA reset count reached");
			k_poll_signal_raise(&apdu->finished, -EIO);
			continue;
		}

		/* Try to send an APDU to the OPTIGA */
		int err = optiga_transfer_apdu(dev, apdu);
		if (err != 0) {
			/* Transfer failed, try to reset the device */
			data->reset_counter++;
			LOG_ERR("APDU transfer failed, reseting OPTIGA, try: %d", data->reset_counter);
			err = optiga_reset(dev);
			if(err != 0) {
				/* If reset fails, something is seriously wrong */
				LOG_ERR("Failed to reset OPTIGA");
			}

			/*
			 * After a reset we need to invalidate all commands in the queue,
			 * because they might use a session context, which is cleared on reset
			 */
			while(apdu != NULL) {
				k_poll_signal_raise(&apdu->finished, -EIO);
				apdu = k_fifo_get(&data->apdu_queue, K_NO_WAIT);
			}

			continue;
		} else {
			/* Successfull transfer, if a problem existed it's solved now */
			data->reset_counter = 0;
		}

		/* Check if an error occured and retrieve it */
		__ASSERT(apdu->rx_len > 0, "Not enough bytes in APDU");
		bool apdu_error = optiga_apdu_is_error(apdu->rx_buf);
		if(apdu_error) {
			u8_t optiga_err_code = 0;
			err = optiga_get_error_code(dev, &optiga_err_code);
			if (err != 0) {
				LOG_ERR("Failed to receive Error Code");
				k_poll_signal_raise(&apdu->finished, err);
				continue;
			}

			k_poll_signal_raise(&apdu->finished, optiga_err_code);
			continue;
		}

		k_poll_signal_raise(&apdu->finished, OPTIGA_STATUS_CODE_SUCCESS);
	}
};

static const struct optiga_api optiga_api_funcs = {
	.optiga_enqueue_apdu = enqueue_apdu,
};

#define OPTIGA_DEVICE(id)						\
static K_THREAD_STACK_DEFINE(optiga_##id##_stack, OPTIGA_STACK_SIZE);	\
	static const struct optiga_cfg optiga_##id##_cfg = {		\
		.i2c_dev_name = DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_BUS_NAME,	\
		.i2c_addr     = DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_BASE_ADDRESS,	\
		.power_pin = DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_POWER_GPIOS_PIN,	\
		.power_flags = DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_POWER_GPIOS_FLAGS,	\
		.power_label = DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_POWER_GPIOS_CONTROLLER,	\
	};								\
									\
static struct optiga_data optiga_##id##_data = {			\
		.worker_stack = optiga_##id##_stack			\
	};								\
									\
DEVICE_AND_API_INIT(optiga_##id, DT_INST_##id##_INFINEON_OPTIGA_TRUST_M_LABEL,	\
		    &optiga_init, &optiga_##id##_data,		\
		    &optiga_##id##_cfg, POST_KERNEL,			\
		    CONFIG_CRYPTO_INIT_PRIORITY, &optiga_api_funcs)

#ifdef DT_INST_0_INFINEON_OPTIGA_TRUST_M
OPTIGA_DEVICE(0);
#endif /* DT_INST_0_INFINEON_OPTIGA_TRUST_M */