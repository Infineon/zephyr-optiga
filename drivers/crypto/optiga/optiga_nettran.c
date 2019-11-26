#include "optiga_nettran.h"
#include "crypto_optiga.h"
#include "optiga_data.h"

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

#define OPTIGA_NETTRAN_OVERHEAD OPTIGA_NETTRAN_HEADER_LEN

int optiga_nettran_init(struct device *dev) {
	return 0;
}

void optiga_nettran_set_chain(u8_t *frame_start, enum OPTIGA_NETTRAN_PCTR_CHAIN chain_mode)
{
	frame_start[OPTIGA_NETTRAN_PCTR_OFFSET] =
		(frame_start[OPTIGA_NETTRAN_PCTR_OFFSET] & ~OPTIGA_NETTRAN_PCTR_CHAIN_MASK) | chain_mode;
}

u8_t optiga_nettran_get_chain(u8_t *frame_start)
{
	return frame_start[OPTIGA_NETTRAN_PCTR_OFFSET] & OPTIGA_NETTRAN_PCTR_CHAIN_MASK;
}

int optiga_nettran_send_apdu(struct device *dev, const u8_t *data, size_t len)
{
	__ASSERT(data, "Invalid NULL pointer");
	u16_t max_packet_size = optiga_data_get_max_packet_size(dev);
	__ASSERT(max_packet_size > OPTIGA_NETTRAN_OVERHEAD, "Packet to small");
	u16_t max_apdu_size =  max_packet_size - OPTIGA_NETTRAN_OVERHEAD;
	struct optiga_data *driver = dev->driver_data;
	u8_t * const packet_buf = driver->nettran.packet_buf;
	packet_buf[OPTIGA_NETTRAN_PCTR_OFFSET] = 0;
	int res = 0;

	/* Handle cases which fit in a single packet */
	if(len <= max_apdu_size) {
		/* write header */
		optiga_nettran_set_chain(packet_buf, OPTIGA_NETTRAN_PCTR_CHAIN_NONE);

		/* write data */
		memcpy(packet_buf + OPTIGA_NETTRAN_PACKET_OFFSET, data, len);

		/* hand over to lower layer */
		res = optiga_data_send_packet(dev, packet_buf, len + OPTIGA_NETTRAN_PCTR_LEN);
		if(res != 0) {
			return res;
		}

		return res;
	}

	const u8_t * cur_data = data;
	size_t remaining_len = len;

	/* First packet */
	optiga_nettran_set_chain(packet_buf, OPTIGA_NETTRAN_PCTR_CHAIN_FIRST);
	memcpy(packet_buf + OPTIGA_NETTRAN_PACKET_OFFSET, cur_data, max_apdu_size);

	res = optiga_data_send_packet(dev, packet_buf, max_packet_size);
	if (res != 0) {
		LOG_ERR("Failed to start chain");
		return res;
	}

	cur_data += max_apdu_size;
	remaining_len -= max_apdu_size;

	/* Send intermediate packets */
	optiga_nettran_set_chain(packet_buf, OPTIGA_NETTRAN_PCTR_CHAIN_INTER);

	while(remaining_len > max_apdu_size) {
		memcpy(packet_buf + OPTIGA_NETTRAN_PACKET_OFFSET, cur_data, max_apdu_size);

		res = optiga_data_send_packet(dev, packet_buf, max_packet_size);
		if (res != 0) {
			LOG_ERR("Failed to send intermediate packet");
			return res;
		}

		cur_data += max_apdu_size;
		remaining_len -= max_apdu_size;
	}

	/* Finish chain */
	optiga_nettran_set_chain(packet_buf, OPTIGA_NETTRAN_PCTR_CHAIN_LAST);

	memcpy(packet_buf + OPTIGA_NETTRAN_PACKET_OFFSET, cur_data, remaining_len);

	/* Don't try to recv data on the last packet, acknowledge will be attached to data */

	res = optiga_data_send_packet(dev, packet_buf, remaining_len + 1);
	if(res != 0) {
		LOG_ERR("Sending last packet failed");
		return res;
	}

	return res;
}

int optiga_nettran_recv_apdu(struct device *dev, u8_t *data, size_t *len)
{
	__ASSERT(data, "Invalid NULL pointer");
	__ASSERT(len, "Invalid NULL pointer");

	size_t buf_len = *len;

	/* TODO: receive buffer must provide space for data + header */
	int res = optiga_data_recv_packet(dev, data, len);

	if (res < 0) {
		LOG_ERR("Failed to read DATA");
		return res;
	}

	u8_t chain = optiga_nettran_get_chain(data);

	if (chain == OPTIGA_NETTRAN_PCTR_CHAIN_NONE) {
		/* No chaining */
		/* Ensure there are enough bytes for header + data */
		__ASSERT(*len >= OPTIGA_NETTRAN_PACKET_OFFSET, "Packet too small");

		/* remove Header */
		*len -= OPTIGA_NETTRAN_PACKET_OFFSET;
		memmove(data, data + OPTIGA_NETTRAN_PACKET_OFFSET, *len);

		return 0;
	} else if (chain == OPTIGA_NETTRAN_PCTR_CHAIN_FIRST) {
		/* chaining, first packet */

		/* Ensure there are enough bytes for header + data */
		__ASSERT(*len >= OPTIGA_NETTRAN_PACKET_OFFSET, "Packet too small");
		u16_t max_packet_size = optiga_data_get_max_packet_size(dev);

		/* remove Header */
		*len -= OPTIGA_NETTRAN_PACKET_OFFSET;
		memmove(data, data + OPTIGA_NETTRAN_PACKET_OFFSET, *len);

		size_t cur_len = *len;
		u8_t *cur_data = data + cur_len;
		*len = buf_len - cur_len;

		res = optiga_data_recv_packet(dev, cur_data, len);
		if (res != 0) {
			LOG_ERR("Failed to read DATA");
			return res;
		}

		chain = optiga_nettran_get_chain(cur_data);

		/* Intermediate packets */
		while(chain == OPTIGA_NETTRAN_PCTR_CHAIN_INTER) {
			/* Intermediate packets must have maximum size */
			__ASSERT(*len == max_packet_size, "Protocol break, packet too small");

			/* remove Header */
			*len -= OPTIGA_NETTRAN_PACKET_OFFSET;
			memmove(cur_data, cur_data + OPTIGA_NETTRAN_PACKET_OFFSET, *len);

			cur_len += *len;
			cur_data = data + cur_len;
			*len = buf_len - cur_len;

			res = optiga_data_recv_packet(dev, cur_data, len);
			if (res != 0) {
				LOG_ERR("Failed to read DATA");
				return res;
			}

			chain = optiga_nettran_get_chain(cur_data);
		}

		if (chain != OPTIGA_NETTRAN_PCTR_CHAIN_LAST) {
			LOG_ERR("Chaining error in chain");
			return -EIO;
		}

		/* remove Header of last packet */
		*len -= OPTIGA_NETTRAN_PACKET_OFFSET;
		memmove(cur_data, cur_data + OPTIGA_NETTRAN_PACKET_OFFSET, *len);

		cur_len += *len;
		*len = cur_len;

		return 0;
	}

	LOG_ERR("Chaining error, need to re-init");
	return -EIO;
}