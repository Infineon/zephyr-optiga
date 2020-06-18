/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/byteorder.h>

#include "tlv_utils.h"

/**
 * @brief Encodes bytes into a Tag Length Value structure
 * @param buf Target buffer for encoded data
 * @param tag Tag value
 * @param val Buffer for Value bytes
 * @param val_len Length of val
 * @return Number of bytes written
 * @note This function does not check for buffer overflow or overflow in Length field
 */
size_t set_tlv(uint8_t *buf, uint8_t tag, const uint8_t *val, uint16_t val_len)
{
	buf[TLV_TAG_OFFS] = tag;
	sys_put_be16(val_len, &buf[TLV_LEN_OFFS]);
	memcpy(&buf[TLV_VAL_OFFS], val, val_len);
	return val_len + TLV_OVERHEAD;
}

size_t set_tlv_u8(uint8_t *buf, uint8_t tag, uint8_t val)
{
	buf[TLV_TAG_OFFS] = tag;
	sys_put_be16(1, &buf[TLV_LEN_OFFS]);
	buf[TLV_VAL_OFFS] = val;
	return SET_TLV_U8_LEN;
}

size_t set_tlv_u16(uint8_t *buf, uint8_t tag, uint16_t val)
{
	buf[TLV_TAG_OFFS] = tag;
	sys_put_be16(2, &buf[TLV_LEN_OFFS]);
	sys_put_be16(val, &buf[TLV_VAL_OFFS]);
	return SET_TLV_U16_LEN;
}

size_t get_tlv(uint8_t *buf, size_t buf_len, uint8_t *tag, uint16_t *len, uint8_t **value)
{
	__ASSERT(buf != NULL, "NULL pointer not allowed");

	if (buf_len < TLV_OVERHEAD) {
		return 0;
	}

	uint8_t *tlv_start = buf;

	if (tag) {
		*tag = *tlv_start;
	}
	tlv_start += TLV_TAG_LEN;

	uint16_t tlv_len = sys_get_be16(tlv_start);

	if (tlv_len > (buf_len - TLV_OVERHEAD)) {
		/* Value field longer than buffer */
		return 0;
	}

	if (len) {
		*len = tlv_len;
	}

	tlv_start += TLV_LEN_LEN;
	if (value) {
		*value = tlv_start;
	}

	return tlv_len + TLV_OVERHEAD;
}