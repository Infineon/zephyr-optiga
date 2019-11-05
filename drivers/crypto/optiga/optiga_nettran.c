#include "optiga_nettran.h"
#include "crypto_optiga.h"
#include "optiga_data.h"

#include <drivers/i2c.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga_nettran);

#define OPTIGA_NETTRAN_PCTR_CHAIN_MASK 0x07
#define OPTIGA_NETTRAN_PCTR_OFFSET 0
#define OPTIGA_NETTRAN_PCTR_LEN 1
#define OPTIGA_NETTRAN_PACKET_OFFSET (OPTIGA_NETTRAN_PCTR_OFFSET + OPTIGA_NETTRAN_PCTR_LEN)

/* CHAIN field in PCTR, see Table 5-1 */
enum OPTIGA_NETTRAN_PCTR_CHAIN {
	OPTIGA_NETTRAN_PCTR_CHAIN_NONE = 0x00,
	OPTIGA_NETTRAN_PCTR_CHAIN_FIRST = 0x01,
	OPTIGA_NETTRAN_PCTR_CHAIN_INTER = 0x02,
	OPTIGA_NETTRAN_PCTR_CHAIN_LAST = 0x04,
	OPTIGA_NETTRAN_PCTR_CHAIN_ERROR = 0x07
};

int optiga_nettran_init(struct device *dev) {
	return 0;
}

void optiga_nettran_set_chain(u8_t *frame_start, enum OPTIGA_NETTRAN_PCTR_CHAIN chain_mode)
{
	frame_start[0] = (frame_start[0] & ~OPTIGA_NETTRAN_PCTR_CHAIN_MASK) | chain_mode;
}

int optiga_nettran_send_apdu(struct device *dev, const u8_t *data, size_t len)
{
	assert(data);
	u16_t max_apdu_size = optiga_data_get_max_packet_size(dev);
	assert(max_apdu_size > OPTIGA_NETTRAN_OVERHEAD);
	max_apdu_size -= OPTIGA_NETTRAN_OVERHEAD;

	// TODO: handle cases where len > max_apdu_size, for now assert on them
	assert(len <= max_apdu_size);

	struct optiga_data *driver = dev->driver_data;
	u8_t * const packet_buf = driver->nettran.packet_buf;

	/* write header */
	packet_buf[OPTIGA_NETTRAN_PCTR_OFFSET] = 0;
	optiga_nettran_set_chain(packet_buf, OPTIGA_NETTRAN_PCTR_CHAIN_NONE);

	/* write data */
	memcpy(packet_buf + OPTIGA_NETTRAN_PACKET_OFFSET, data, len);

	/* hand over to lower layer */
	return optiga_data_send_packet(dev, packet_buf, len + OPTIGA_NETTRAN_PCTR_LEN);
}