/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_

#include <device.h>

#include "optiga_phy.h"

/*
 * 1 byte  FCTR
 * 2 bytes LEN
 */
#define OPTIGA_DATA_HEADER_LEN 3

/* 2 bytes FCS */
#define OPTIGA_DATA_TRAILER_LEN 2

#define OPTIGA_DATA_BUF_SIZE (OPTIGA_PHY_BUF_SIZE - OPTIGA_DATA_HEADER_LEN - OPTIGA_DATA_TRAILER_LEN)

struct data_link_layer {
	size_t frame_len;
	u8_t frame_buf[OPTIGA_PHY_BUF_SIZE];
	u8_t frame_tx_nr; /* next transmit frame number */
	u8_t frame_tx_ack;/* last received ack number for transmitted frame */
	u8_t frame_rx_nr; /* last received frame number */
};

int optiga_data_init(struct device *dev);
u16_t optiga_data_get_max_packet_size(struct device *dev);
int optiga_data_send_packet(struct device *dev, const u8_t *packet, size_t len);
int optiga_data_recv_packet(struct device *dev, u8_t *data, size_t *data_len);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_ */