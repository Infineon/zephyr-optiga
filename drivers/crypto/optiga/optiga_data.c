#include "crypto_optiga.h"
#include "optiga_phy.h"
#include "optiga_data.h"

#include <drivers/i2c.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga_data);

/* Length in bytes of the fields in a frame, see Figure 3-1 in protocol specification */
#define OPTIGA_DATA_FCTR_LEN 1
#define OPTIGA_DATA_LEN_LEN 2
#define OPTIGA_DATA_FCS_LEN 2

/* Offsets in frame header */
#define OPTIGA_DATA_FCTR_OFFSET 0
#define OPTIGA_DATA_LEN_OFFSET (OPTIGA_DATA_FCTR_OFFSET + OPTIGA_DATA_FCTR_LEN)
#define OPTIGA_DATA_PACKET_START_OFFSET (OPTIGA_DATA_LEN_OFFSET + OPTIGA_DATA_LEN_LEN)

/* Flags in the FCTR */
enum {
	/* FTYPE field */
	OPTIGA_DATA_FCTR_FTYPE_DATA = 0x00,
	OPTIGA_DATA_FCTR_FTYPE_CTRL = 0x80,
	/* SEQCTR field */
	OPTIGA_DATA_FCTR_SEQCTR_ACK = 0x00,
	OPTIGA_DATA_FCTR_SEQCTR_NAK = 0x20,
	OPTIGA_DATA_FCTR_SEQCTR_RST = 0x40
};

/* Length of a sync frame is fixed */
#define OPTIGA_DATA_CRTL_FRAME_LEN (OPTIGA_DATA_FCTR_LEN + OPTIGA_DATA_LEN_LEN + OPTIGA_DATA_FCS_LEN)
#if DATA_REG_LEN < OPTIGA_DATA_CRTL_FRAME_LEN
#error "Can't fit smallest frame in send buffer"
#endif

/*
 * Inner function of the FCS, initial seed is 0
 * From Appendix 8.1.2 of the protocol specification
 */
u16_t optiga_data_calc_fcs_core(u16_t seed, u8_t c)
{
	u16_t h1, h2, h3, h4;
	h1 = (seed ^ c) & 0xFF;
	h2 = h1 & 0x0F;
	h3 = (h2 << 4) ^ h1;
	h4 = h3 >> 4;
	return (((((h3 << 1) ^ h4) << 4) ^ h2) << 3) ^ h4 ^ (seed >> 8);
}

u16_t optiga_data_frame_calc_fcs(u8_t *frame_start, size_t len)
{
	/* Initial seed is 0 */
	u16_t fcs = 0;
	for(size_t i = 0; i < len; i++) {
		optiga_data_calc_fcs_core(fcs, frame_start[i]);
	}

	return fcs;
}

void optiga_data_frame_set_len(u8_t *frame_start, u16_t len_value)
{
	frame_start[OPTIGA_DATA_LEN_OFFSET] = len_value >> 8;
	frame_start[OPTIGA_DATA_LEN_OFFSET + 1] = len_value;
}

void optiga_data_frame_set_fctr(u8_t *frame_start, u8_t flags)
{
	frame_start[OPTIGA_DATA_FCTR_OFFSET] = flags;
}

/* len is the size of the frame header + packet data */
void optiga_data_frame_set_fcs(u8_t *frame_start, size_t len)
{
	u16_t fcs = optiga_data_frame_calc_fcs(frame_start, len);
	/* Chapter 3.3 says, order of FCS is: Low Byte || High Byte */
	frame_start[len] = fcs;
	frame_start[len + 1] = fcs >> 8;
}

int optiga_send_sync_frame(struct device *dev)
{
	struct optiga_data *driver = dev->driver_data;
	u8_t *frame = driver->data.frame_buf;
	/* Assemble frame data */
	optiga_data_frame_set_fctr(frame, OPTIGA_DATA_FCTR_FTYPE_CTRL | OPTIGA_DATA_FCTR_SEQCTR_RST);
	optiga_data_frame_set_len(frame, 0);
	optiga_data_frame_set_fcs(frame, OPTIGA_DATA_PACKET_START_OFFSET);
	driver->data.frame_len = OPTIGA_DATA_CRTL_FRAME_LEN;

	return optiga_phy_write_data(dev, frame, OPTIGA_DATA_CRTL_FRAME_LEN);
}

int optiga_data_init(struct device *dev)
{
	/* Bring to a known state */
	int err = optiga_send_sync_frame(dev);
	if (err != 0) {
		LOG_ERR("Failed to send sync frame");
		return err;
	}

	LOG_DBG("Data Link init successful");

	return 0;
}
