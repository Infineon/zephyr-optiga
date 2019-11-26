#include "optiga_phy.h"
#include "crypto_optiga.h"

#include <drivers/i2c.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga_phy);

/* Register addresses as per protocol specification Table 2-1 */
#define OPTIGA_REG_ADDR_DATA			0x80
#define OPTIGA_REG_ADDR_DATA_REG_LEN		0x81
#define OPTIGA_REG_ADDR_I2C_STATE		0x82
#define OPTIGA_REG_ADDR_BASE_ADDR		0x83
#define OPTIGA_REG_ADDR_MAX_SCL_FREQU		0x84
#define OPTIGA_REG_ADDR_GUARD_TIME		0x85
#define OPTIGA_REG_ADDR_TRANS_TIMEOUT		0x86
#define OPTIGA_REG_ADDR_PWR_SAVE_TIMEOUT	0x87
#define OPTIGA_REG_ADDR_SOFT_RESET		0x88
#define OPTIGA_REG_ADDR_I2C_MODE		0x89

#define OPTIGA_DELAYED_ACK_TRIES 5
#define OPTIGA_DELAYED_ACK_TIME_MS 10

#define OPTIGA_STATUS_POLL_TRIES 5
#define OPTIGA_STATUS_POLL_TIME_MS 10

/* highest byte of the I2C_STATE register */
#define OPTIGA_REG_I2C_STATE_BUSY		(1<<7)
#define OPTIGA_REG_I2C_STATE_RESP_RDY		(1<<6)

int optiga_delayed_ack_write(struct device *dev, const u8_t *data, size_t len)
{
	struct optiga_data *driver = dev->driver_data;
	const struct optiga_cfg *config = dev->config->config_info;

	bool acked = false;
	int res = 0;
	int i = 0;
	for(i = 0; i < OPTIGA_DELAYED_ACK_TRIES; i++) {
		res = i2c_write(driver->i2c_master, data, len, config->i2c_addr);
		if (res == 0) {
			acked = true;
			break;
		}
		k_sleep(OPTIGA_DELAYED_ACK_TIME_MS);
	}

	if (!acked) {
		LOG_DBG("No ACK received");
		return -EIO;
	}

	LOG_DBG("ACK after %d tries", i);
	return 0;
}

int optiga_reg_read(struct device *dev, u8_t addr, u8_t *data, size_t len)
{
	if (len == 0) {
		LOG_WRN("Can't read 0 bytes");
		return -EINVAL;
	}

	struct optiga_data *driver = dev->driver_data;
	const struct optiga_cfg *config = dev->config->config_info;

	/* select register for read */
	int res = optiga_delayed_ack_write(dev, &addr, sizeof(addr));
	if (res != 0) {
		return res;
	}

	/* Guard time required by OPTIGA chip between I2C transactions */
	k_busy_wait(50);

	/* Read data */
	bool acked = false;
	int i = 0;
	for(i = 0; i < OPTIGA_DELAYED_ACK_TRIES; i++) {
		res = i2c_read(driver->i2c_master, data, len, config->i2c_addr);
		if (res == 0) {
			acked = true;
			break;
		}
		k_sleep(OPTIGA_DELAYED_ACK_TIME_MS);
	}

	if (!acked) {
		LOG_DBG("No ACK for read data received");
		return -EIO;
	}

	LOG_DBG("Read ACK after %d tries", i);

	return res;
}

int optiga_reg_write(struct device *dev, u8_t addr, const u8_t *data, size_t len)
{
	struct optiga_data *driver = dev->driver_data;
	u8_t *reg_write_buf = driver->phy.reg_write_buf;

	if (len > (CONFIG_OPTIGA_HOST_BUFFER_SIZE - 1)) {
		LOG_DBG("Not enough memory for write buffer");
		return -ENOMEM;
	}

	*reg_write_buf = addr;
	reg_write_buf++;
	memcpy(reg_write_buf, data, len);

	int res = optiga_delayed_ack_write(dev, driver->phy.reg_write_buf, len + 1);

	return res;
}

/* Poll until BUSY flag is cleared or timeout */
static bool optiga_poll_status(struct device *dev, u8_t mask, u8_t value)
{
	bool tmp_rdy = false;
	int i;
	u8_t reg = 0;
	/* Try only a finite number of times */
	for (i = 0; i < OPTIGA_STATUS_POLL_TRIES; i++) {
		int res = optiga_reg_read(dev, OPTIGA_REG_ADDR_I2C_STATE, &reg, 1);
		if (res < 0) {
			LOG_DBG("I2C error");
			return false;
		}

		if ((reg & mask) == value) {
			/* data available*/
			tmp_rdy = true;
			break;
		}

		/* give the device more time */
		k_sleep(OPTIGA_STATUS_POLL_TIME_MS);
	}

	if(!tmp_rdy) {
		LOG_DBG("STATE: mask: 0x%02x, expected: 0x%02x, reg: 0x%02x, tries: %d, ", mask, value, reg, i);
	}

	return tmp_rdy;
}

/* Can not use optiga_reg_write because the send buffer might not be setup correctly */
int optiga_soft_reset(struct device *dev) {
	static const u8_t reset_cmd[] = {OPTIGA_REG_ADDR_SOFT_RESET, 0x00, 0x00};

	LOG_DBG("Performing soft reset");
	return optiga_delayed_ack_write(dev, reset_cmd, sizeof(reset_cmd));
}

/* Can not use optiga_reg_write because the send buffer might not be setup correctly */
int optiga_set_data_reg_len(struct device *dev, u16_t data_reg_len) {
	const u8_t cmd[] = {OPTIGA_REG_ADDR_SOFT_RESET, data_reg_len >> 8, data_reg_len};

	return optiga_delayed_ack_write(dev, cmd, sizeof(cmd));
}

int optiga_get_data_reg_len(struct device *dev, u16_t* data_reg_len) {
	__ASSERT(data_reg_len != NULL, "Invalid NULL pointer");

	u8_t raw[2] = {0};
	int err = optiga_reg_read(dev, OPTIGA_REG_ADDR_DATA_REG_LEN, raw, 2);
	if (err != 0) {
		LOG_DBG("Failed to read DATA_REG_LEN register");
		return err;
	}

	*data_reg_len = ((u16_t)raw[0]) << 8 | raw[1];

	return 0;
}

int optiga_negotiate_data_reg_len(struct device *dev) {
	/* read the value from the device */
	u16_t data_reg_len = 0;
	int err = optiga_get_data_reg_len(dev, &data_reg_len);
	if(err != 0) {
		return err;
	}

	if (data_reg_len > DATA_REG_LEN) {
		/* apply our maximum value */
		err = optiga_set_data_reg_len(dev, DATA_REG_LEN);
		if(err != 0) {
			return err;
		}

		/* read back, to ensure the value is correctly applied */
		err = optiga_get_data_reg_len(dev, &data_reg_len);
		if(err != 0) {
			return err;
		}

		if (data_reg_len != DATA_REG_LEN) {
			return -EINVAL;
		}
	} else if (data_reg_len < OPTIGA_DATA_REG_LEN_MIN) {
		LOG_ERR("Received invalid DATA_REG_LEN");
		return -EINVAL;
	}

	struct optiga_data *driver = dev->driver_data;
	driver->phy.data_reg_len = data_reg_len;
	LOG_DBG("Negotiated DATA_REG_LEN: %d", data_reg_len);
	return 0;
}

int optiga_get_i2c_state(struct device *dev, u16_t* read_len, u8_t* state_flags)
{
	u8_t raw[4] = {0};
	int err = optiga_reg_read(dev, OPTIGA_REG_ADDR_I2C_STATE, raw, 4);
	if (err != 0) {
		LOG_DBG("Failed to read DATA_REG_LEN register");
		return err;
	}

	/* Bits 16-23 are ignored because they are RFU */
	if (read_len) {
		*read_len = ((u16_t)raw[2]) << 8 | raw[3];
	}

	if (state_flags) {
		*state_flags = raw[0];
	}

	return 0;
}

int optiga_phy_init(struct device *dev) {
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
	err = optiga_get_i2c_state(dev, &read_len, &flags);
	if (err != 0) {
		LOG_ERR("Failed to read I2C_STATE");
		return err;
	}

	LOG_DBG("Read len: %d, state flags: 0x%02x", read_len, flags);

	return 0;
}

int optiga_phy_read_data(struct device *dev, u8_t *data, size_t *len, u8_t *flags)
{
	__ASSERT(data, "Invalid NULL pointer");
	__ASSERT(len, "Invalid NULL pointer");

	/* Don't check BUSY here, because prevents reading of the last ack frame for an APDU */
	if(!optiga_poll_status(dev, OPTIGA_REG_I2C_STATE_RESP_RDY, OPTIGA_REG_I2C_STATE_RESP_RDY)) {
		optiga_get_i2c_state(dev, NULL, NULL);
		LOG_ERR("No response available");
		return -EIO;
	}

	uint16_t read_len = 0;
	int err = optiga_get_i2c_state(dev, &read_len, flags);
	if (err != 0) {
		LOG_ERR("Failed to get data length");
		return err;
	}

	if (*len < read_len) {
		LOG_ERR("Receive buffer too small");
		return -ENOMEM;
	}

	err = optiga_reg_read(dev, OPTIGA_REG_ADDR_DATA, data, read_len);
	if (err != 0) {
		LOG_DBG("Failed to read DATA register");
		return err;
	}

	*len = read_len;
	LOG_HEXDUMP_INF(data, *len, "PHY read:");
	return 0;
}

int optiga_phy_write_data(struct device *dev, const u8_t *data, size_t len)
{
	__ASSERT(data, "Invalid NULL pointer");


	if(!optiga_poll_status(dev, OPTIGA_REG_I2C_STATE_BUSY, 0)) {
		optiga_get_i2c_state(dev, NULL, NULL);
		LOG_ERR("BUSY flag not cleared");
		return -EIO;
	}

	LOG_HEXDUMP_INF(data, len, "PHY write:");

	return optiga_reg_write(dev, OPTIGA_REG_ADDR_DATA, data, len);
}

u16_t optiga_phy_get_data_reg_len(struct device *dev)
{
	struct optiga_data *driver = dev->driver_data;
	return driver->phy.data_reg_len;
}
