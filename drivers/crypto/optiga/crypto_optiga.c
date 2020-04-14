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

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga);

#define OPTIGA_SHIELD_STACK_ADDITION (128 + 64)

// determined by experiment
#define OPTIGA_STACK_SIZE (512+256 + OPTIGA_SHIELD_STACK_ADDITION)
// TODO(chr): make Kconfig tunable
#define OPTIGA_THREAD_PRIORITY 1
#define OPTIGA_MAX_RESET 3
#define OPTIGA_HIBERNATE_DELAY_MS 1000

enum OPTIGA_SHIELD_STATE {
	OPTIGA_SHIELD_DISABLED = 0,
	OPTIGA_SHIELD_LOADING_KEY,
	OPTIGA_SHIELD_KEY_LOADED,
	OPTIGA_SHIELD_HANDSHAKE,
	OPTIGA_SHIELD_ENABLED,
};

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
/* Only least significant byte */
#define OPTIGA_LEN_OFFS 3

/* Resets the state of the stack */
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

	err = optiga_pre_init(dev);
	if(err != 0) {
		LOG_ERR("Failed to initialise OPTIGA presentation layer");
		return err;
	}

	return err;
}

static bool optiga_apdu_is_error(u8_t *apdu_start)
{
	return apdu_start[OPTIGA_APDU_STA_OFFSET] != OPTIGA_APDU_STA_SUCCESS;
}

static int optiga_get_error_code(struct device *dev, u8_t *err_code)
{
	__ASSERT(dev, "Invalid NULL pointer");
	__ASSERT(err_code, "Invalid NULL pointer");

	int err = optiga_pre_send_apdu(dev,
		error_code_apdu,
		sizeof(error_code_apdu));
	if(err != 0) {
		LOG_ERR("Failed to send Error Code APDU");
		return err;
	}

	u8_t tmp_buf[OPTIGA_GET_ERROR_RESPONSE_LEN] = {0};
	size_t tmp_buf_len = OPTIGA_GET_ERROR_RESPONSE_LEN;


	err = optiga_pre_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (err != 0) {
		LOG_INF("Failed to get Error Code APDU response");
		return err;
	}

	/* Expected APDU return length is always 5 */
	if (tmp_buf_len != OPTIGA_GET_ERROR_RESPONSE_LEN) {
		LOG_ERR("Unexpected response length");
		return -EIO;
	}

	if (optiga_apdu_is_error(tmp_buf)) {
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

static const u8_t optiga_open_application_apdu[OPTIGA_OPEN_APPLICATION_LEN] =
{
	0xF0, /* command code */
	0x00, /* Param */
	0x00, 0x10, /* 16 bytes parameter */
	/* unique application identifier */
	0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C,
};

/* Param value to restore application state from Hibernation */
#define OPTIGA_OPEN_APP_PARAM_RESTORE 0x01
/* Length value for restore command */
#define OPTIGA_OPEN_APP_LENGTH (16 + OPTIGA_CTX_HANDLE_LEN)

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

	LOG_HEXDUMP_INF(handle, handle ? OPTIGA_CTX_HANDLE_LEN : 0, "Restore ctx handle:");

	memcpy(tmp_buf, optiga_open_application_apdu, OPTIGA_OPEN_APPLICATION_LEN);

	if (handle == NULL) {
		tmp_buf_len = OPTIGA_OPEN_APPLICATION_LEN;
	} else {
		tmp_buf[OPTIGA_PARAM_OFFS] = OPTIGA_OPEN_APP_PARAM_RESTORE;
		tmp_buf[OPTIGA_LEN_OFFS] = OPTIGA_OPEN_APP_LENGTH;
		memcpy(tmp_buf + OPTIGA_OPEN_APPLICATION_LEN, handle, OPTIGA_CTX_HANDLE_LEN);
		tmp_buf_len = OPTIGA_RESTORE_APPLICATION_LEN;
	}

	int err = optiga_pre_send_apdu(dev, tmp_buf, tmp_buf_len);
	if (err != 0) {
		LOG_ERR("Failed to send OpenApplication APDU");
		return err;
	}

	/* Expected response to "OpenApplication" */
	static const u8_t resp[OPTIGA_OPEN_APPLICATION_RESPONSE_LEN] = {0};
	static const size_t resp_len = OPTIGA_OPEN_APPLICATION_RESPONSE_LEN;

	tmp_buf_len = OPTIGA_RESTORE_APPLICATION_LEN;
	err = optiga_pre_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (err != 0) {
		LOG_INF("Failed to get OpenApplication APDU response");
		return err;
	}

	if(resp_len != tmp_buf_len || memcmp(tmp_buf, resp, resp_len)) {
		LOG_HEXDUMP_ERR(tmp_buf, tmp_buf_len, "Unexpected response1: ");
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

/* Param value to Hibernate the application */
#define OPTIGA_CLOSE_APP_PARAM_HIBERNATE 0x01

static int optiga_close_application(struct device *dev, u8_t *handle)
{
	u8_t tmp_buf[OPTIGA_CTX_HANDLE_LEN + OPTIGA_APDU_OUT_DATA_OFFSET] = {0};
	size_t tmp_buf_len = 0;
	struct optiga_data *data = dev->driver_data;

	memcpy(tmp_buf, optiga_close_application_apdu, OPTIGA_CLOSE_APPLICATION_LEN);
	tmp_buf_len = OPTIGA_CLOSE_APPLICATION_LEN;

	if (handle != NULL) {
		tmp_buf[OPTIGA_PARAM_OFFS] = OPTIGA_CLOSE_APP_PARAM_HIBERNATE;
	}

	int err = optiga_pre_send_apdu(dev, tmp_buf, tmp_buf_len);
	if(err != 0) {
		LOG_ERR("Failed to send OpenApplication APDU");
		return err;
	}

	tmp_buf_len = OPTIGA_CTX_HANDLE_LEN + OPTIGA_APDU_OUT_DATA_OFFSET;
	err = optiga_pre_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (err != 0) {
		LOG_INF("Failed to get OpenApplication APDU response");
		return err;
	}

	if (handle != NULL) {
		if (tmp_buf_len == OPTIGA_APDU_OUT_DATA_OFFSET && optiga_apdu_is_error(tmp_buf)) {
			LOG_INF("OPTIGA not ready for hibernate");
			return -EIO;
		} else if (tmp_buf_len != (OPTIGA_CTX_HANDLE_LEN + OPTIGA_APDU_OUT_DATA_OFFSET))
		{
			LOG_HEXDUMP_ERR(tmp_buf, tmp_buf_len, "Unexpected response2: ");
			return -EIO;
		}

		memcpy(handle, tmp_buf + OPTIGA_APDU_OUT_DATA_OFFSET, OPTIGA_CTX_HANDLE_LEN);
	} else {
		if (tmp_buf_len != 4 || optiga_apdu_is_error(tmp_buf)) {
			LOG_HEXDUMP_ERR(tmp_buf, tmp_buf_len, "Unexpected response3: ");
			return -EIO;
		}
	}

	LOG_HEXDUMP_INF(handle, handle ? OPTIGA_CTX_HANDLE_LEN : 0, "Hibernate ctx handle:");

	data->open = false;
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

	/* bring the protocol stack to a known state */
	int err = optiga_reset(dev);
	if (err != 0) {
		return err;
	}

	err = optiga_open_application(dev, NULL);
	if(err != 0) {
		return err;
	}

	atomic_set(&data->shield_state, OPTIGA_SHIELD_DISABLED);

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
	int err = optiga_pre_send_apdu(dev,	apdu->tx_buf, apdu->tx_len);
	if(err != 0) {
		LOG_ERR("Failed to send APDU");
		return err;
	}

	err = optiga_pre_recv_apdu(dev, apdu->rx_buf, &apdu->rx_len);
	if (err != 0) {
		LOG_ERR("Failed to receive APDU");
		return err;
	}

	return err;
}

/* Puts the OPTIGA into Hibernate mode if possible */
static void optiga_hibernate(struct device *dev)
{
	struct optiga_data *data = dev->driver_data;

	/*
	 * Session contexts in OPTIGA_IGNORE_HIBERNATE_MASK are saved via the
	 * "Close Application" command, don't let them prevent shutdown.
	 */
	atomic_t reservations = atomic_get(&data->session_reservations);
	/* Check for wake locks preventing hibernate */
	if (reservations & ~OPTIGA_IGNORE_HIBERNATE_MASK) {
		return;
	}

	/* Can power down OPTIGA */
	bool save_ctx = reservations & OPTIGA_IGNORE_HIBERNATE_MASK;
	int res = optiga_close_application(dev, save_ctx ? data->hibernate_handle : NULL);
	if (res != 0) {
		LOG_INF("OPTIGA not ready for Hibernate");
		return;
	}

	if (atomic_get(&data->shield_state) == OPTIGA_SHIELD_ENABLED) {
		res = optiga_pre_save_ctx(dev);
		if (res != 0) {
			LOG_WRN("Couldn't save Shield state");
			/* Need to re-handshake */
			atomic_set(&data->shield_state, OPTIGA_SHIELD_KEY_LOADED);
		}
	}

	optiga_power(dev, false);
}

/* Wakes the OPTIGA from Hibernate mode */
static void optiga_wakup(struct device *dev)
{
	struct optiga_data *data = dev->driver_data;

	optiga_power(dev, true);

	/* bring the protocol stack to a known state */
	int err = optiga_phy_init(dev);
	if(err != 0) {
		LOG_ERR("Failed to initialise OPTIGA phy layer");
		return;
	}

	err = optiga_data_init(dev);
	if(err != 0) {
		LOG_ERR("Failed to initialise OPTIGA data link layer");
		return;
	}

	// TODO(chr): possible to skip?
	err = optiga_nettran_init(dev);
	if(err != 0) {
		LOG_ERR("Failed to initialise OPTIGA nettran layer");
		return;
	}

	/* Don't re-init optiga_pre, to avoid loosing the keys */

	if (atomic_get(&data->shield_state) == OPTIGA_SHIELD_ENABLED) {
		optiga_nettran_presence_enable(dev);
		int res = optiga_pre_restore_ctx(dev);
		if (res != 0) {
			LOG_WRN("Coulnd't restore Shield state");
			atomic_set(&data->shield_state, OPTIGA_SHIELD_KEY_LOADED);
		} else {
			LOG_INF("Shield restored");
		}
	}

	atomic_t reservations = atomic_get(&data->session_reservations);
	bool restore_ctx = reservations & OPTIGA_IGNORE_HIBERNATE_MASK;

	// TODO(chr): error handling
	optiga_open_application(dev, restore_ctx ? data->hibernate_handle : NULL);
}

enum WORKER_STATE {
	WORKER_IDLE,
	WORKER_HIBERNATE,
	WORKER_PROCESS_APDU,
	WORKER_RESET,
	WORKER_RESET_LOCK,
};

static void optiga_worker(void* arg1, void *arg2, void *arg3)
{
	struct device *dev = arg1;
	struct optiga_data *data = dev->driver_data;
	k_thread_name_set(k_current_get(), "OPTIGA driver");
	enum WORKER_STATE state = WORKER_IDLE;
	struct optiga_apdu *apdu = NULL;
	int err = 0;

	/* execute forevever */
	while (true) {
		switch(state) {
			case WORKER_IDLE:
				apdu = k_fifo_get(&data->apdu_queue, OPTIGA_HIBERNATE_DELAY_MS);
				if (apdu == NULL) {
					/* Hibernate delay elapsed, try to hibernate */
					state = WORKER_HIBERNATE;
				} else {
					/* Process the APDU */
					state = WORKER_PROCESS_APDU;
				}
				break;
			case WORKER_HIBERNATE:
				/* Try to hibernate */
				optiga_hibernate(dev);

				if (data->open) {
					/* Couldn't hibernate, try again later */
					state = WORKER_IDLE;
					break;
				}

				/* Wait for new APDUs */
				apdu = k_fifo_get(&data->apdu_queue, K_FOREVER);

				/* Wake OPTIGA from hibernate to handle APDU */
				optiga_wakup(dev);

				if (!data->open) {
					/* Signal error to users and mark APDU as handled */
					k_poll_signal_raise(&apdu->finished, err);
					apdu = NULL;

					/* Couldn't wake OPTIGA, try reset */
					state = WORKER_RESET;
					break;
				}

				/* Successfull wakup, if a problem existed it's solved now */
				data->reset_counter = 0;
				state = WORKER_PROCESS_APDU;
				break;
			case WORKER_PROCESS_APDU:
				__ASSERT(apdu != NULL, "No APDU to process");
				__ASSERT(data->open, "OPTIGA must be opened");

				/* Check if we need to execute the handshake for shielded connection*/
				if (atomic_cas(&data->shield_state, OPTIGA_SHIELD_KEY_LOADED, OPTIGA_SHIELD_HANDSHAKE)) {
					err = optiga_pre_do_handshake(dev);
					if (err == 0) {
						LOG_INF("Shielded Connection enabled");
						atomic_set(&data->shield_state, OPTIGA_SHIELD_ENABLED);
					} else {
						LOG_ERR("Handshake failed: %d", err);
						atomic_set(&data->shield_state, OPTIGA_SHIELD_KEY_LOADED);

						/* Signal error to users and mark APDU as handled */
						k_poll_signal_raise(&apdu->finished, -EIO);
						apdu = NULL;

						/* Need to clear out APDUs that rely on encryption being present */
						state = WORKER_RESET;
						break;
					}
				}

				/* Try to send an APDU to the OPTIGA */
				err = optiga_transfer_apdu(dev, apdu);
				if (err != 0) {
					/* Forward error to users and mark APDU as handled */
					k_poll_signal_raise(&apdu->finished, err);
					apdu = NULL;

					/* Transfer failed, try to reset the device */
					state = WORKER_RESET;
					break;
				} else {
					/* Successfull transfer, if a problem existed it's solved now */
					data->reset_counter = 0;
				}

				if (optiga_nettran_presence_get(dev) && optiga_pre_need_rehandshake(dev)) {
					if (atomic_cas(&data->shield_state, OPTIGA_SHIELD_ENABLED, OPTIGA_SHIELD_KEY_LOADED)) {
						LOG_INF("Executing re-handshake");
					}
				}

				/* Check if APDU signals an error and retrieve it */
				__ASSERT(apdu->rx_len > 0, "Not enough bytes in APDU");
				if(optiga_apdu_is_error(apdu->rx_buf)) {
					u8_t optiga_err_code = 0;
					err = optiga_get_error_code(dev, &optiga_err_code);
					if (err != 0) {
						LOG_ERR("Failed to receive Error Code: %d", err);

						/* Forward error to users and mark APDU as handled */
						k_poll_signal_raise(&apdu->finished, err);
						apdu = NULL;

						/* Transfer failed, try to reset the device */
						state = WORKER_RESET;
						break;
					}

					if (optiga_nettran_presence_get(dev) && optiga_pre_need_rehandshake(dev)) {
						if (atomic_cas(&data->shield_state, OPTIGA_SHIELD_ENABLED, OPTIGA_SHIELD_KEY_LOADED)) {
							LOG_INF("Executing re-handshake");
						}
					}

					/* Forward OPTIGA error code to users, mark APDU as handled */
					k_poll_signal_raise(&apdu->finished, optiga_err_code);
					apdu = NULL;
					break;
				}

				/* APDU transferred without error, mark as handled */
				k_poll_signal_raise(&apdu->finished, OPTIGA_STATUS_CODE_SUCCESS);
				apdu = NULL;

				state = WORKER_IDLE;
				break;
			case WORKER_RESET:
				__ASSERT(apdu == NULL, "APDU must be marked as handled");

				data->reset_counter++;

				if (data->reset_counter == OPTIGA_MAX_RESET) {
					/* Final power down */
					LOG_ERR("Maximum reset count reached, turning off");
					optiga_power(dev, false);
					state = WORKER_RESET_LOCK;
					break;
				}

				LOG_ERR("Reseting OPTIGA, try: %d", data->reset_counter);

				/* bring the protocol stack to a known state */
				err = optiga_reset(dev);
				if (err != 0) {
					/* If reset fails, something is seriously wrong */
					LOG_ERR("Failed to reset protocol stack");
				}

				if (err == 0) {
					err = optiga_open_application(dev, NULL);
					if(err != 0) {
						/* If OpenApplication fails, something is seriously wrong */
						LOG_ERR("Failed to do OpenApplication");
					}
				}

				/*
				 * After a reset we need to invalidate all commands in the queue,
				 * because they might use a session context, which is cleared on reset
				 */
				while((apdu = k_fifo_get(&data->apdu_queue, K_NO_WAIT)) != NULL) {
					k_poll_signal_raise(&apdu->finished, -EIO);

				}

				/* If shielded connection was enabled, we need to re-handshake*/
				atomic_cas(&data->shield_state, OPTIGA_SHIELD_ENABLED, OPTIGA_SHIELD_KEY_LOADED);
				break;
			case WORKER_RESET_LOCK:
				/* Wait for new APDUs */
				apdu = k_fifo_get(&data->apdu_queue, K_FOREVER);

				/* Signal error to user */
				k_poll_signal_raise(&apdu->finished, -EIO);

				/* This state is a permanent dead end until re-initialization of the driver */
				break;
		}
	}

};

/* Acquire a session context. It must be returned via optiga_session_release.
 * Returns false if the requested token is not available
 */
static bool session_acquire(struct device *dev, int session_idx)
{
	struct optiga_data *data = dev->driver_data;
	bool acquired = !atomic_test_and_set_bit(&data->session_reservations, session_idx);

	return acquired;
}

static void session_release(struct device *dev, int session_idx)
{
	struct optiga_data *data = dev->driver_data;
	atomic_clear_bit(&data->session_reservations, session_idx);
}

static int start_shield(struct device *dev, const u8_t *key, size_t key_len)
{
	struct optiga_data *data = dev->driver_data;
	const bool prev_disabled = atomic_cas(&data->shield_state, OPTIGA_SHIELD_DISABLED, OPTIGA_SHIELD_LOADING_KEY);
	const bool prev_loaded =  atomic_cas(&data->shield_state, OPTIGA_SHIELD_KEY_LOADED, OPTIGA_SHIELD_LOADING_KEY);
	if (prev_disabled || prev_loaded) {
		int res = optiga_pre_set_shared_secret(dev, key, key_len);
		if (res != 0) {
			/* Can only happen with invalid key */
			LOG_ERR("Failed to set key: %d", res);
			if (prev_disabled) {
				atomic_set(&data->shield_state, OPTIGA_SHIELD_DISABLED);
			} else {
				atomic_set(&data->shield_state, OPTIGA_SHIELD_KEY_LOADED);
			}
			return res;
		}

		atomic_set(&data->shield_state, OPTIGA_SHIELD_KEY_LOADED);
		return 0;
	}

	return -EALREADY;
}

static const struct optiga_api optiga_api_funcs = {
	.optiga_enqueue_apdu = enqueue_apdu,
	.optiga_session_acquire = session_acquire,
	.optiga_session_release = session_release,
	.optiga_start_shield = start_shield,
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