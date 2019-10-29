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

int optiga_reg_read(struct device *dev, u8_t addr, u8_t *data, size_t len)
{
	struct optiga_data *driver = dev->driver_data;
	const struct optiga_cfg *config = dev->config->config_info;

	/* select register for read */
	bool acked = false;
	int res = 0;
	int i = 0;
	for(i = 0; i < 5; i++) {
		res = i2c_write(driver->i2c_master, &addr, sizeof(addr), config->i2c_addr);
		if (res == 0) {
			acked = true;
			break;
		}
		k_sleep(10);
	}

	if (!acked) {
		LOG_DBG("No ACK for register address received");
		return -EIO;
	}

	LOG_DBG("Reg ACK after %d tries", i);

	/* Guard time required by OPTIGA chip between I2C transactions */
	k_busy_wait(50);

	/* Read data */
	acked = false;
	for(i = 0; i < 5; i++) {
		res = i2c_read(driver->i2c_master, data, len, config->i2c_addr);
		if (res == 0) {
			acked = true;
			break;
		}
		k_sleep(10);
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
	const struct optiga_cfg *config = dev->config->config_info;
	u8_t *reg_write_buf = driver->phy.reg_write_buf;

	if (len > (REG_WRITE_BUF_SIZE - 1)) {
		LOG_DBG("Not enough memory for write buffer");
		return -ENOMEM;
	}

	*reg_write_buf = addr;
	reg_write_buf++;
	memcpy(reg_write_buf, data, len);

	bool acked = false;
	int res = 0;
	int i = 0;
	for(i = 0; i < 5; i++) {
		res = i2c_write(driver->i2c_master,  driver->phy.reg_write_buf, len + 1, config->i2c_addr);
		if (res == 0) {
			acked = true;
			break;
		}
		k_sleep(10);
	}

	if (!acked) {
		LOG_DBG("No ACK for write received");
		return -EIO;
	}

	LOG_DBG("Write ACK after %d tries", i);

	return res;
}

/* Can not use optiga_reg_write because the send buffer might not be setup correctly */
int optiga_soft_reset(struct device *dev) {
	struct optiga_data *driver = dev->driver_data;
	const struct optiga_cfg *config = dev->config->config_info;
	static const u8_t reset_cmd[] = {OPTIGA_REG_ADDR_SOFT_RESET, 0x00, 0x00};

	bool acked = false;
	int res = 0;
	int i = 0;
	for(i = 0; i < 5; i++) {
		res = i2c_write(driver->i2c_master,  reset_cmd, sizeof(reset_cmd), config->i2c_addr);
		if (res == 0) {
			acked = true;
			break;
		}
		k_sleep(10);
	}

	if (!acked) {
		LOG_DBG("No ACK for soft reset cmd received");
		return -EIO;
	}

	LOG_DBG("Soft reset ACK after %d tries", i);

	return res;
}

int optiga_phy_init(struct device *dev) {

}
