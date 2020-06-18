/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_TRUST_M_TLV_UTILS_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_TRUST_M_TLV_UTILS_H_

#define TLV_TAG_LEN 1
#define TLV_LEN_LEN 2

#define TLV_TAG_OFFS 0
#define TLV_LEN_OFFS (TLV_TAG_OFFS + TLV_TAG_LEN)
#define TLV_VAL_OFFS (TLV_LEN_OFFS + TLV_LEN_LEN)

#define TLV_OVERHEAD (TLV_TAG_LEN + TLV_LEN_LEN)

#define SET_TLV_U8_LEN 4
#define SET_TLV_U16_LEN 5

size_t set_tlv(uint8_t *buf, uint8_t tag, const uint8_t *val, uint16_t val_len);
size_t set_tlv_u8(uint8_t *buf, uint8_t tag, uint8_t val);
size_t set_tlv_u16(uint8_t *buf, uint8_t tag, uint16_t val);
size_t get_tlv(uint8_t *buf, size_t buf_len, uint8_t *tag, uint16_t *len, uint8_t **value);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_TRUST_M_TLV_UTILS_H_ */