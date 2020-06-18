/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "optiga_phy.h"
#include "crypto_optiga.h"

#include <drivers/i2c.h>
#include <sys/byteorder.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(optiga_phy, CONFIG_CRYPTO_LOG_LEVEL);

/* Protocol limits from Table 2-1 */
#define OPTIGA_DATA_REG_LEN_MAX 0xFFFF
#define OPTIGA_DATA_REG_LEN_MIN 0x10

#if OPTIGA_PHY_DATA_REG_LEN < OPTIGA_DATA_REG_LEN_MIN || OPTIGA_PHY_DATA_REG_LEN > OPTIGA_DATA_REG_LEN_MAX
#error "DATA_REG_LEN outside protocol limits"
#endif

/* Register addresses as per protocol specification Table 2-1 */
#define OPTIGA_REG_ADDR_DATA                    0x80
#define OPTIGA_REG_ADDR_DATA_REG_LEN            0x81
#define OPTIGA_REG_ADDR_I2C_STATE               0x82
#define OPTIGA_REG_ADDR_BASE_ADDR               0x83
#define OPTIGA_REG_ADDR_MAX_SCL_FREQU           0x84
#define OPTIGA_REG_ADDR_GUARD_TIME              0x85
#define OPTIGA_REG_ADDR_TRANS_TIMEOUT           0x86
#define OPTIGA_REG_ADDR_PWR_SAVE_TIMEOUT        0x87
#define OPTIGA_REG_ADDR_SOFT_RESET              0x88
#define OPTIGA_REG_ADDR_I2C_MODE                0x89

#define OPTIGA_DELAYED_ACK_TRIES 20
#define OPTIGA_DELAYED_ACK_TIME K_MSEC(8)

/* Need 32s timeout here, because RSA2048 key generation takes long */
#define OPTIGA_STATUS_POLL_TRIES 4000
#define OPTIGA_STATUS_POLL_TIME K_MSEC(8)

/* Helper function for late acknowledge write transfers */
int optiga_late_ack_write(struct device *dev, const uint8_t *data, size_t len)
{
	struct optiga_data *driver = dev->driver_data;
	const struct optiga_cfg *config = dev->config_info;

	bool acked = false;
	int res = 0;
	int i = 0;

	/* Try writing until maximum number of tries is reached */
	for (i = 0; i < OPTIGA_DELAYED_ACK_TRIES; i++) {
		res = i2c_write(driver->i2c_master, data, len, config->i2c_addr);
		if (res == 0) {
			/* Write transfer successful */
			acked = true;
			break;
		}
		k_sleep(OPTIGA_DELAYED_ACK_TIME);
	}

	if (!acked) {
		/* Error during write transfer */
		LOG_ERR("No ACK received");
		return -EIO;
	}

	LOG_DBG("ACK after %d tries", i);
	return 0;
}

/**
 * @brief Reads from a register of the given device
 * @param dev Device to work with
 * @param addr Register address to read
 * @param data Output buffer for the read data
 * @param len Number of bytes to read from the register
 * @note data must be at least len bytes
 */
int optiga_reg_read(struct device *dev, uint8_t addr, uint8_t *data, size_t len)
{
	__ASSERT(len > 0, "Can't read 0 bytes");

	struct optiga_data *driver = dev->driver_data;
	const struct optiga_cfg *config = dev->config_info;

	/* select register for read */
	int res = optiga_late_ack_write(dev, &addr, sizeof(addr));

	if (res != 0) {
		return res;
	}

	/* Guard time required by OPTIGA chip between I2C transactions */
	k_busy_wait(50);

	/* Read data */
	bool acked = false;
	int i = 0;

	for (i = 0; i < OPTIGA_DELAYED_ACK_TRIES; i++) {
		res = i2c_read(driver->i2c_master, data, len, config->i2c_addr);
		if (res == 0) {
			acked = true;
			break;
		}
		k_sleep(OPTIGA_DELAYED_ACK_TIME);
	}

	if (!acked) {
		LOG_ERR("No ACK for read data received");
		return -EIO;
	}

	LOG_DBG("Read ACK after %d tries", i);

	return res;
}

/**
 * @brief Writes to a register of the given device
 * @param dev Device to work with
 * @param addr Register address to write
 * @param len Number of bytes to write to the register
 * @note The data to write is taken from the host buffer to avoid copies.
 */
int optiga_reg_write(struct device *dev, uint8_t addr, size_t len)
{
	struct optiga_data *driver = dev->driver_data;

	if (len > (CONFIG_OPTIGA_HOST_BUFFER_SIZE - 1)) {
		LOG_DBG("Not enough memory for write buffer");
		return -ENOMEM;
	}

	driver->phy.host_buf[0] = addr;

	return optiga_late_ack_write(dev, driver->phy.host_buf, len + 1);
}

/*
 * @brief Poll status flags until the expected value is read or a timeout occurs
 *
 * Polls the status flags, apply a mask on the content and compares with an expected value.
 * Tries a maximum of OPTIGA_STATUS_POLL_TRIES with a delay of OPTIGA_STATUS_POLL_TIME_MS
 * in between.
 *
 * @param dev Device to poll
 * @param mask Mask to applied on the status flags
 * @param value Expected value
 * @return True if the expecte value was retrieved, false on timeout or error
 */
bool optiga_poll_status(struct device *dev, uint8_t mask, uint8_t value)
{
	bool tmp_rdy = false;
	int i;
	uint8_t reg = 0;

	/* Try only a finite number of times */
	for (i = 0; i < OPTIGA_STATUS_POLL_TRIES; i++) {
		int res = optiga_reg_read(dev, OPTIGA_REG_ADDR_I2C_STATE, &reg, 1);
		if (res < 0) {
			return false;
		}

		if ((reg & mask) == value) {
			/* data available*/
			tmp_rdy = true;
			break;
		}

		/* give the device more time */
		k_sleep(OPTIGA_STATUS_POLL_TIME);
	}

	if (!tmp_rdy) {
		LOG_ERR("mask: 0x%02x, expected: 0x%02x, reg: 0x%02x, tries: %d", mask, value, reg, i);
	}

	return tmp_rdy;
}

int optiga_soft_reset(struct device *dev)
{
	/* ensure host buffer is big enough for reset command */
	BUILD_ASSERT((sizeof(uint16_t) + 1) <= CONFIG_OPTIGA_HOST_BUFFER_SIZE,
		     "Host buffer too small for essential command");

	uint8_t *tx_buf = optiga_phy_frame_buf(dev, NULL);

	sys_put_be16(0, tx_buf);

	LOG_DBG("Performing soft reset");
	return optiga_reg_write(dev, OPTIGA_REG_ADDR_SOFT_RESET, sizeof(uint16_t));
}

int optiga_set_data_reg_len(struct device *dev, uint16_t data_reg_len)
{
	/* ensure host buffer is big enough for DATA_REG_LEN command */
	BUILD_ASSERT((sizeof(uint16_t) + 1) <= CONFIG_OPTIGA_HOST_BUFFER_SIZE,
		     "Host buffer too small for essential command");

	uint8_t *tx_buf = optiga_phy_frame_buf(dev, NULL);

	sys_put_be16(data_reg_len, tx_buf);
	return optiga_reg_write(dev, OPTIGA_REG_ADDR_SOFT_RESET, sizeof(uint16_t));
}

int optiga_get_data_reg_len(struct device *dev, uint16_t *data_reg_len)
{
	__ASSERT(data_reg_len != NULL, "Invalid NULL pointer");

	uint8_t raw[2] = { 0 };
	int err = optiga_reg_read(dev, OPTIGA_REG_ADDR_DATA_REG_LEN, raw, 2);

	if (err != 0) {
		LOG_ERR("Failed to read DATA_REG_LEN register");
		return err;
	}

	*data_reg_len = sys_get_be16(raw);

	return 0;
}

int optiga_negotiate_data_reg_len(struct device *dev)
{
	/* read the value from the device */
	uint16_t data_reg_len = 0;
	int err = optiga_get_data_reg_len(dev, &data_reg_len);

	if (err != 0) {
		return err;
	}

	if (data_reg_len < OPTIGA_DATA_REG_LEN_MIN) {
		LOG_ERR("Received invalid DATA_REG_LEN");
		return -EINVAL;
	}

	if (data_reg_len > OPTIGA_PHY_DATA_REG_LEN) {
		/* reduce device value to our maximum value */
		err = optiga_set_data_reg_len(dev, OPTIGA_PHY_DATA_REG_LEN);
		if (err != 0) {
			return err;
		}

		/* read back, to ensure the value is correctly applied */
		err = optiga_get_data_reg_len(dev, &data_reg_len);
		if (err != 0) {
			return err;
		}

		if (data_reg_len != OPTIGA_PHY_DATA_REG_LEN) {
			return -EINVAL;
		}
	}

	struct optiga_data *driver = dev->driver_data;

	driver->phy.data_reg_len = data_reg_len;
	LOG_DBG("Negotiated DATA_REG_LEN: %d", data_reg_len);
	return 0;
}

int optiga_phy_get_i2c_state(struct device *dev, uint16_t *read_len, uint8_t *state_flags)
{
	uint8_t raw[4] = { 0 };
	int err = optiga_reg_read(dev, OPTIGA_REG_ADDR_I2C_STATE, raw, 4);

	if (err != 0) {
		LOG_DBG("Failed to read DATA_REG_LEN register");
		return err;
	}

	/* Bits 16-23 are ignored because they are RFU */
	if (read_len) {
		*read_len = sys_get_be16(&raw[2]);
	}

	if (state_flags) {
		*state_flags = raw[0];
	}

	LOG_DBG("I2C_STATE: Read len %d, state flags: 0x%02x", sys_get_be16(&raw[2]), raw[0]);

	return 0;
}

int optiga_phy_init(struct device *dev)
{
	/* bring the device to a known state */
	int err = optiga_soft_reset(dev);

	if (err != 0) {
		LOG_ERR("Failed to perform soft reset");
		return err;
	}

	/* Negotiate DATA_REG_LEN */
	err = optiga_negotiate_data_reg_len(dev);
	if (err != 0) {
		LOG_ERR("Failed to negotiate DATA_REG_LEN");
		return err;
	}

	/* print the state of the device */
	uint16_t read_len = 0;
	uint8_t flags = 0;

	err = optiga_phy_get_i2c_state(dev, &read_len, &flags);
	if (err != 0) {
		LOG_ERR("Failed to read I2C_STATE");
		return err;
	}

	LOG_DBG("Read len: %d, state flags: 0x%02x", read_len, flags);

	return 0;
}

/**
 * @brief Get the buffer to write frames
 * @param dev Device to access
 * @param len If not NULL, return the length of the buffer
 * @return Pointer to the buffer for frame data
 */
inline uint8_t *optiga_phy_frame_buf(struct device *dev, size_t *len)
{
	struct optiga_data *driver = dev->driver_data;

	if (len) {
		*len = driver->phy.data_reg_len;
	}

	return driver->phy.host_buf + OPTIGA_PHY_HEADER_LEN;
}

int optiga_phy_read_frame(struct device *dev, size_t *len)
{
	__ASSERT(len, "Invalid NULL pointer");

	/* Don't check BUSY here, because it prevents reading of the last ack frame for an APDU */
	if (!optiga_poll_status(dev, OPTIGA_I2C_STATE_FLAG_RESP_READY, OPTIGA_I2C_STATE_FLAG_RESP_READY)) {
		LOG_ERR("No response available");
		return -EIO;
	}

	uint16_t read_len = 0;
	int err = optiga_phy_get_i2c_state(dev, &read_len, NULL);

	if (err != 0) {
		LOG_ERR("Failed to get data length");
		return err;
	}

	size_t data_buf_len = 0;
	uint8_t *data_buf = optiga_phy_frame_buf(dev, &data_buf_len);

	__ASSERT(read_len <= data_buf_len, "Receive buffer too small");

	err = optiga_reg_read(dev, OPTIGA_REG_ADDR_DATA, data_buf, read_len);
	if (err != 0) {
		LOG_DBG("Failed to read DATA register");
		return err;
	}

	*len = read_len;
	LOG_HEXDUMP_DBG(data_buf, *len, "PHY DATA read:");
	return 0;
}

int optiga_phy_write_frame(struct device *dev, size_t len)
{
	if (!optiga_poll_status(dev, OPTIGA_I2C_STATE_FLAG_BUSY, 0)) {
		optiga_phy_get_i2c_state(dev, NULL, NULL);
		LOG_ERR("BUSY flag not cleared");
		return -EIO;
	}

	LOG_HEXDUMP_DBG(optiga_phy_frame_buf(dev, NULL), len, "PHY DATA write:");

	return optiga_reg_write(dev, OPTIGA_REG_ADDR_DATA, len);
}
