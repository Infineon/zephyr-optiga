#include "crypto_optiga.h"
#include "optiga_phy.h"
#include "optiga_data.h"

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

#define OPTIGA_DATA_FCTR_FTYPE_MASK 0x80
#define OPTIGA_DATA_FCTR_SEQCTR_MASK 0x60
#define OPTIGA_DATA_FCTR_FRNR_MASK 0x0C
#define OPTIGA_DATA_FCTR_ACKNR_MASK 0x03

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

#define OPTIG_DATA_FRAME_POLL_TIME_MS 10
#define OPTIG_DATA_FRAME_RETRY_CNT 3

#define DATA_LINK_OVERHEAD (OPTIGA_DATA_HEADER_LEN + OPTIGA_DATA_TRAILER_LEN)

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

u16_t optiga_data_frame_calc_fcs(const u8_t *frame_start, size_t len)
{
	/* Initial seed is 0 */
	u16_t fcs = 0;
	for(size_t i = 0; i < len; i++) {
		fcs = optiga_data_calc_fcs_core(fcs, frame_start[i]);
	}

	return fcs;
}

/*
 * param len is the number of bytes including the FCS
 * retval true if the FCS is correct, false else
 */
bool optiga_data_frame_check_fcs(const u8_t *frame_start, size_t len)
{
	if (len < OPTIGA_DATA_FCS_LEN) {
		LOG_DBG("Not enough bytes");
		return false;
	}

	u16_t calc_fcs = optiga_data_frame_calc_fcs(frame_start, len - 2);
	u16_t recv_fcs = frame_start[len - 1];
	recv_fcs |= frame_start[len - 2] << 8;

	return calc_fcs == recv_fcs;
}

void optiga_data_frame_set_len(u8_t *frame_start, u16_t len_value)
{
	frame_start[OPTIGA_DATA_LEN_OFFSET] = len_value >> 8;
	frame_start[OPTIGA_DATA_LEN_OFFSET + 1] = len_value;
}

u16_t optiga_data_frame_get_len(u8_t *frame_start)
{
	u16_t len = frame_start[OPTIGA_DATA_LEN_OFFSET] << 8;
	len |= frame_start[OPTIGA_DATA_LEN_OFFSET + 1];
	return len;
}

void optiga_data_frame_set_fctr(u8_t *frame_start, u8_t flags, u8_t frame_nr, u8_t frame_ack)
{
	/* ensure no bits are written outside their fields */
	assert(!(flags & ~(OPTIGA_DATA_FCTR_FTYPE_MASK|OPTIGA_DATA_FCTR_SEQCTR_MASK)));
	assert(!(frame_nr & 0xf3));
	assert(!(frame_ack & 0xfc));

	frame_start[OPTIGA_DATA_FCTR_OFFSET] = flags | frame_nr << 2 | frame_ack;
}

/* len is the size of the frame header + packet data */
void optiga_data_frame_set_fcs(u8_t *frame_start, size_t len)
{
	u16_t fcs = optiga_data_frame_calc_fcs(frame_start, len);
	/* Chapter 3.3 says, order of FCS is: Low Byte || High Byte */
	frame_start[len] = fcs >> 8;
	frame_start[len + 1] = fcs;
}

int optiga_send_sync_frame(struct device *dev)
{
	struct optiga_data *driver = dev->driver_data;
	u8_t *frame = driver->data.frame_buf;
	/* Assemble frame data */
	optiga_data_frame_set_fctr(frame, OPTIGA_DATA_FCTR_FTYPE_CTRL | OPTIGA_DATA_FCTR_SEQCTR_RST, 0, 0);
	optiga_data_frame_set_len(frame, 0);
	optiga_data_frame_set_fcs(frame, OPTIGA_DATA_PACKET_START_OFFSET);
	driver->data.frame_len = OPTIGA_DATA_CRTL_FRAME_LEN;

	return optiga_phy_write_data(dev, frame, OPTIGA_DATA_CRTL_FRAME_LEN);
}

/* send a packet with the correct framing */
int optiga_data_send_packet(struct device *dev, const u8_t *packet, size_t len)
{
	u16_t data_reg_len = optiga_phy_get_data_reg_len(dev);
	if((len + DATA_LINK_OVERHEAD) > data_reg_len) {
		LOG_ERR("Packet too big");
		return -EINVAL;
	}

	struct optiga_data *driver = dev->driver_data;
	u8_t * const frame = driver->data.frame_buf;
	u8_t * const frame_nr = &driver->data.frame_nr;
	u8_t * const frame_ack = &driver->data.frame_ack;

	/* Assemble frame header */
	optiga_data_frame_set_fctr(frame, OPTIGA_DATA_FCTR_FTYPE_DATA | OPTIGA_DATA_FCTR_SEQCTR_ACK, *frame_nr, *frame_ack);
	optiga_data_frame_set_len(frame, len);
	/* Copy packet data */
	memcpy(frame + OPTIGA_DATA_PACKET_START_OFFSET, packet, len);
	optiga_data_frame_set_fcs(frame, OPTIGA_DATA_PACKET_START_OFFSET + len);
	driver->data.frame_len = len + DATA_LINK_OVERHEAD;

	return optiga_phy_write_data(dev, frame, driver->data.frame_len);
}

bool optiga_data_is_ctrl_frame(const u8_t *frame_start)
{
	return (frame_start[OPTIGA_DATA_FCTR_OFFSET] & OPTIGA_DATA_FCTR_FTYPE_MASK) == OPTIGA_DATA_FCTR_FTYPE_CTRL;
}

u8_t optiga_data_get_seqctr(const u8_t *frame_start) {
	return frame_start[OPTIGA_DATA_FCTR_OFFSET] & OPTIGA_DATA_FCTR_SEQCTR_MASK;
}

u8_t optiga_data_get_frame_nr(const u8_t *frame_start) {
	return (frame_start[OPTIGA_DATA_FCTR_OFFSET] & OPTIGA_DATA_FCTR_FRNR_MASK) >> 2;
}

u8_t optiga_data_get_ack_nr(const u8_t *frame_start) {
	return frame_start[OPTIGA_DATA_FCTR_OFFSET] & OPTIGA_DATA_FCTR_ACKNR_MASK;
}

/*
 * retval 0 means a frame was received, check data_len for the amounts of bytes received
 * retval 1 means a frame needed to be retransmitted, try again
 * retval 2 means the device is still busy processing the frame
 * data is always invalidated
 * retval <0 means fatal error, re-init needed
 */
int optiga_data_recv_frame(struct device *dev, u8_t *data, size_t *data_len)
{
	u8_t flags = 0;
	/* TODO: The receive buffer does not take into account the headers */
	int err = optiga_phy_read_data(dev, data, data_len, &flags);
	if (err != 0) {
		LOG_ERR("Failed to read I2C_STATE");
		return err;
	}

	LOG_DBG("Read len: %d, state flags: 0x%02x", *data_len, flags);

	if (flags & OPTIGA_I2C_STATE_FLAG_BUSY) {
		LOG_DBG("Device busy");
		return 2;
	}

	if (!(flags & OPTIGA_I2C_STATE_FLAG_RESP_READY)) {
		/* TODO: Do we always get a response? */
		LOG_DBG("No response ready, asume busy");
		return 2;
	}

	if (*data_len == 0) {
		LOG_DBG("No response available");
		return 0;
	}

	if (*data_len < OPTIGA_DATA_CRTL_FRAME_LEN) {
		LOG_ERR("Frame too small");
		return -EIO;
	}

	/* Check FCS */
	bool fcs_good = optiga_data_frame_check_fcs(data, *data_len);
	/* TODO: handle transmission errors */
	assert(fcs_good);


	/* Frame header parsing */
	u8_t seqctr = optiga_data_get_seqctr(data);

	/* TODO: handle NAK and SYNC frames */
	assert(seqctr == OPTIGA_DATA_FCTR_SEQCTR_ACK);

	/* check ack matches sent frame */
	u8_t ack_nr = optiga_data_get_ack_nr(data);
	struct optiga_data *driver = dev->driver_data;
	u8_t *sent_frame = driver->data.frame_buf;
	u8_t prev_frame_nr = optiga_data_get_frame_nr(sent_frame);

	/* TODO: handle wrong ack received errors */
	assert(prev_frame_nr == ack_nr);

	/* Previous frame nr was acknowledged, increase frame number for next send action */
	driver->data.frame_nr = (driver->data.frame_nr + 1) % 4;

	bool ctrl_frame = optiga_data_is_ctrl_frame(data);
	u16_t frame_len = optiga_data_frame_get_len(data);
	if (ctrl_frame) {
		LOG_DBG("Control frame");
		assert(frame_len == 0);
		*data_len = 0;
		return 0;
	}

	LOG_DBG("Data frame");

	/* Ensure frame lenght matches */
	assert((frame_len + DATA_LINK_OVERHEAD) == *data_len)

	/* Remove frame header */
	memmove(data, &data[OPTIGA_DATA_PACKET_START_OFFSET], frame_len);
	*data_len = frame_len;
	return 0;
}

u16_t optiga_data_get_max_packet_size(struct device *dev)
{
	u16_t data_reg_len = optiga_phy_get_data_reg_len(dev);
	assert(data_reg_len > DATA_LINK_OVERHEAD);
	return data_reg_len - DATA_LINK_OVERHEAD;
}

int optiga_data_init(struct device *dev)
{
	/* Bring to a known state */
	int err = optiga_send_sync_frame(dev);
	if (err != 0) {
		LOG_ERR("Failed to send sync frame");
		return err;
	}

	struct optiga_data *driver = dev->driver_data;
	driver->data.frame_nr = 0;
	driver->data.frame_ack = 0;
	driver->data.retry_cnt = 0;

	LOG_DBG("Data Link init successful");

	return 0;
}


