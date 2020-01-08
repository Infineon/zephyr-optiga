/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_
#define ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_

#include <device.h>

/*
 * 1 byte  FCTR
 * 2 bytes LEN
 */
#define OPTIGA_DATA_HEADER_LEN 3

/* 2 bytes FCS */
#define OPTIGA_DATA_TRAILER_LEN 2

struct data_link_layer {
	u8_t frame_tx_nr; /* next transmit frame number */
	u8_t frame_tx_ack;/* last received ack number for transmitted frame */
	u8_t frame_rx_nr; /* last received frame number */
};

int optiga_data_init(struct device *dev);
u8_t *optiga_data_packet_buf(struct device *dev, size_t *len);
int optiga_data_send_packet(struct device *dev, size_t len);
int optiga_data_recv_packet(struct device *dev, size_t *data_len);

#endif /* ZEPHYR_DRIVERS_CRYPTO_OPTIGA_OPTIGA_DATA_H_ */