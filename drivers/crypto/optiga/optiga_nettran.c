/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
	size_t max_packet_size = 0;
	u8_t *packet_buf = optiga_data_packet_buf(dev, &max_packet_size);

	__ASSERT(max_packet_size > OPTIGA_NETTRAN_OVERHEAD, "Packet size to small");
	size_t max_apdu_size =  max_packet_size - OPTIGA_NETTRAN_OVERHEAD;
	packet_buf[OPTIGA_NETTRAN_PCTR_OFFSET] = 0;
	int res = 0;

	/* Handle cases which fit in a single packet */
	if(len <= max_apdu_size) {
		/* write header */
		optiga_nettran_set_chain(packet_buf, OPTIGA_NETTRAN_PCTR_CHAIN_NONE);

		/* write data */
		memcpy(packet_buf + OPTIGA_NETTRAN_PACKET_OFFSET, data, len);

		/* hand over to lower layer */
		res = optiga_data_send_packet(dev, len + OPTIGA_NETTRAN_PCTR_LEN);
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

	res = optiga_data_send_packet(dev, max_packet_size);
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

		res = optiga_data_send_packet(dev, max_packet_size);
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

	res = optiga_data_send_packet(dev, remaining_len + 1);
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

	size_t buf_len = 0;
	int res = optiga_data_recv_packet(dev, &buf_len);
	if (res != 0) {
		LOG_ERR("Failed to read DATA");
		return res;
	}

	/* Ensure there are enough bytes for header + data */
	__ASSERT(buf_len >= OPTIGA_NETTRAN_PACKET_OFFSET, "Packet too small");

	size_t max_packet_size = 0;
	u8_t *buf = optiga_data_packet_buf(dev, &max_packet_size);

	u8_t chain = optiga_nettran_get_chain(buf);

	if (chain == OPTIGA_NETTRAN_PCTR_CHAIN_NONE) {
		/* No chaining */
		/* remove Header */
		buf_len -= OPTIGA_NETTRAN_PACKET_OFFSET;
		if (*len < buf_len) {
			return -ENOMEM;
		}

		*len = buf_len;
		memcpy(data, buf + OPTIGA_NETTRAN_PACKET_OFFSET, buf_len);

		return 0;
	} else if (chain == OPTIGA_NETTRAN_PCTR_CHAIN_FIRST) {
		/* chaining, first packet */

		/* remove Header */
		buf_len -= OPTIGA_NETTRAN_PACKET_OFFSET;
		if (*len < buf_len) {
			return -ENOMEM;
		}

		memcpy(data, buf + OPTIGA_NETTRAN_PACKET_OFFSET, buf_len);

		size_t cur_len = buf_len;
		u8_t *cur_data = data + cur_len;
		buf_len = 0;

		res = optiga_data_recv_packet(dev, &buf_len);
		if (res != 0) {
			LOG_ERR("Failed to read DATA");
			return res;
		}

		/* Ensure there are enough bytes for header + data */
		__ASSERT(buf_len >= OPTIGA_NETTRAN_PACKET_OFFSET, "Packet too small");

		buf = optiga_data_packet_buf(dev, NULL);
		chain = optiga_nettran_get_chain(buf);

		/* Intermediate packets */
		while(chain == OPTIGA_NETTRAN_PCTR_CHAIN_INTER) {
			/* Intermediate packets must have maximum size */
			__ASSERT(buf_len == max_packet_size, "Protocol break, packet too small");

			/* remove Header */
			buf_len -= OPTIGA_NETTRAN_PACKET_OFFSET;
			cur_len += buf_len;

			if (cur_len > *len) {
				return -ENOMEM;
			}

			memcpy(cur_data, buf + OPTIGA_NETTRAN_PACKET_OFFSET, buf_len);

			cur_data = data + cur_len;
			buf_len = 0;

			res = optiga_data_recv_packet(dev, &buf_len);
			if (res != 0) {
				LOG_ERR("Failed to read DATA");
				return res;
			}

			/* Ensure there are enough bytes for header + data */
			__ASSERT(buf_len >= OPTIGA_NETTRAN_PACKET_OFFSET, "Packet too small");

			buf = optiga_data_packet_buf(dev, NULL);
			chain = optiga_nettran_get_chain(buf);
		}

		if (chain != OPTIGA_NETTRAN_PCTR_CHAIN_LAST) {
			LOG_ERR("Chaining error in chain");
			return -EIO;
		}

		/* Ensure there are enough bytes for header + data */
		__ASSERT(buf_len >= OPTIGA_NETTRAN_PACKET_OFFSET, "Packet too small");

		/* remove Header of last packet */
		buf_len -= OPTIGA_NETTRAN_PACKET_OFFSET;
		cur_len += buf_len;

		if (cur_len > *len) {
			return -ENOMEM;
		}

		memcpy(cur_data, buf + OPTIGA_NETTRAN_PACKET_OFFSET, buf_len);

		*len = cur_len;

		return 0;
	}

	LOG_ERR("Chaining error, need to re-init");
	return -EIO;
}