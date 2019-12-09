#include "crypto_optiga.h"
#include "optiga_phy.h"
#include "optiga_data.h"

#include <sys/byteorder.h>

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
	u16_t recv_fcs = sys_get_be16(&frame_start[len - 2]);

	return calc_fcs == recv_fcs;
}

void optiga_data_frame_set_len(u8_t *frame_start, u16_t len_value)
{
	sys_put_be16(len_value, &frame_start[OPTIGA_DATA_LEN_OFFSET]);
}

u16_t optiga_data_frame_get_len(u8_t *frame_start)
{
	return sys_get_be16(&frame_start[OPTIGA_DATA_LEN_OFFSET]);
}

void optiga_data_frame_set_fctr(u8_t *frame_start, u8_t flags, u8_t frame_nr, u8_t frame_ack)
{
	/* ensure no bits are written outside their fields */
	__ASSERT(!(flags & ~(OPTIGA_DATA_FCTR_FTYPE_MASK|OPTIGA_DATA_FCTR_SEQCTR_MASK)), "Invalid flags");
	__ASSERT(!(frame_nr & 0xfc), "Invalid frame_nr");
	__ASSERT(!(frame_ack & 0xfc), "Invalid ack_nr");

	frame_start[OPTIGA_DATA_FCTR_OFFSET] = flags | frame_nr << 2 | frame_ack;
}

/* len is the size of the frame header + packet data */
void optiga_data_frame_set_fcs(u8_t *frame_start, size_t len)
{
	u16_t fcs = optiga_data_frame_calc_fcs(frame_start, len);
	/* Chapter 3.3 says, order of FCS is: Low Byte || High Byte */
	sys_put_be16(fcs, &frame_start[len]);
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

int optiga_send_sync_frame(struct device *dev)
{
	// TODO(chr): check length and out of bounds write
	u8_t *frame = optiga_phy_data_buf(dev, NULL);
	/* Assemble frame data */
	optiga_data_frame_set_fctr(frame, OPTIGA_DATA_FCTR_FTYPE_CTRL | OPTIGA_DATA_FCTR_SEQCTR_RST, 0, 0);
	optiga_data_frame_set_len(frame, 0);
	optiga_data_frame_set_fcs(frame, OPTIGA_DATA_PACKET_START_OFFSET);

	return optiga_phy_write_data(dev, OPTIGA_DATA_CRTL_FRAME_LEN);
}

int optiga_send_ack_frame(struct device *dev)
{
	// TODO(chr): check length and out of bounds write
	u8_t *frame = optiga_phy_data_buf(dev, NULL);

	/*
	 * Sending an ack frame would destroy the read buffer, so we backup
	 * the relevant bytes before sending and restore them afterwards.
	 * This works, because PHY doesn't have trailing bytes in the frame.
	 */
	u8_t frame_bak[OPTIGA_DATA_CRTL_FRAME_LEN];
	memcpy(frame_bak, frame, OPTIGA_DATA_CRTL_FRAME_LEN);

	/* Assemble frame data */
	struct optiga_data *driver = dev->driver_data;
	optiga_data_frame_set_fctr(frame, OPTIGA_DATA_FCTR_FTYPE_CTRL | OPTIGA_DATA_FCTR_SEQCTR_ACK, 0, driver->data.frame_rx_nr);
	optiga_data_frame_set_len(frame, 0);
	optiga_data_frame_set_fcs(frame, OPTIGA_DATA_PACKET_START_OFFSET);

	int err = optiga_phy_write_data(dev, OPTIGA_DATA_CRTL_FRAME_LEN);

	/* restore previous frame content */
	memcpy(frame, frame_bak, OPTIGA_DATA_CRTL_FRAME_LEN);
	return err;
}

int optiga_data_is_ctrl_frame_available(struct device *dev)
{
	u16_t read_len = 0;
	int res = optiga_get_i2c_state(dev, &read_len, NULL);
	if(res != 0) {
		return res;
	}

	if(read_len == OPTIGA_DATA_CRTL_FRAME_LEN) {
		return 1;
	}

	return 0;
}

int optiga_data_recv_ctrl_frame(struct device *dev)
{
	size_t ctrl_fram_len = 0;
	int err = optiga_phy_read_data(dev, &ctrl_fram_len);
	if (err != 0) {
		LOG_ERR("Failed to read I2C_STATE");
		return err;
	}

	LOG_DBG("CTRL len: %d", ctrl_fram_len);

	if (ctrl_fram_len == 0) {
		LOG_DBG("No response available");
		return 0;
	}

	if (ctrl_fram_len != OPTIGA_DATA_CRTL_FRAME_LEN) {
		LOG_ERR("Invalid frame");
		return -EIO;
	}

	u8_t* ctrl_frame_buf = optiga_phy_data_buf(dev, NULL);

	/* Check FCS */
	bool fcs_good = optiga_data_frame_check_fcs(ctrl_frame_buf, ctrl_fram_len);
	if(!fcs_good) {
		/* TODO: handle transmission errors */
		return -EIO;
	}

	/* Frame header parsing */
	u8_t seqctr = optiga_data_get_seqctr(ctrl_frame_buf);

	if (seqctr != OPTIGA_DATA_FCTR_SEQCTR_ACK) {
		LOG_ERR("Packet not acked");
		return -EIO;
	}

	/* check ack matches sent frame */
	u8_t ack_nr = optiga_data_get_ack_nr(ctrl_frame_buf);
	struct optiga_data *driver = dev->driver_data;

	if(driver->data.frame_tx_nr == ack_nr) {
		/* frame nr was acknowledged, increase frame number for next send action */
		driver->data.frame_tx_nr = (driver->data.frame_tx_nr + 1) % 4;
		/* make this ack our last received one */
		driver->data.frame_tx_ack = ack_nr;
	} else if (driver->data.frame_tx_ack == ack_nr) {
		LOG_DBG("Received same ACK twice");
	} else 	{
		LOG_ERR("Wrong frame acknowledged");
		//return -EIO;
	}

	bool ctrl_frame = optiga_data_is_ctrl_frame(ctrl_frame_buf);
	u16_t frame_len = optiga_data_frame_get_len(ctrl_frame_buf);
	if (!ctrl_frame || frame_len != 0) {
		LOG_ERR("Invalid control frame");
		return -EIO;
	}

	return 0;
}

/* send a packet with the correct framing */
int optiga_data_send_packet(struct device *dev, size_t len)
{
	size_t max_frame_len = 0;
	u8_t * const frame = optiga_phy_data_buf(dev, &max_frame_len);
	if((len + DATA_LINK_OVERHEAD) > max_frame_len) {
		LOG_ERR("Packet too big");
		return -EINVAL;
	}

	struct optiga_data *driver = dev->driver_data;
	u8_t * const frame_nr = &driver->data.frame_tx_nr;
	u8_t * const frame_ack = &driver->data.frame_rx_nr;

	/* Assemble frame header */
	optiga_data_frame_set_fctr(frame, OPTIGA_DATA_FCTR_FTYPE_DATA | OPTIGA_DATA_FCTR_SEQCTR_ACK, *frame_nr, *frame_ack);
	optiga_data_frame_set_len(frame, len);
	optiga_data_frame_set_fcs(frame, OPTIGA_DATA_PACKET_START_OFFSET + len);

	int res = optiga_phy_write_data(dev, len + DATA_LINK_OVERHEAD);
	if (res != 0) {
		LOG_ERR("Can't send data to phy");
		return res;
	}

	res = optiga_data_is_ctrl_frame_available(dev);
	if (res < 0) {
		LOG_ERR("Can't check for controll frame");
		return res;
	}

	if (res == 1) {
		LOG_INF("Ctrl frame available, receiving");
		return optiga_data_recv_ctrl_frame(dev);
	}

	LOG_INF("No Ctrl frame available");
	return 0;
}

int optiga_data_recv_packet(struct device *dev, size_t *data_len)
{
	// TODO: This function has code duplication with optiga_data_recv_ctrl_frame(...)
	size_t rx_data_len = 0;
	int err = optiga_phy_read_data(dev, &rx_data_len);
	if (err != 0) {
		LOG_ERR("Failed to read I2C_STATE");
		return err;
	}

	LOG_DBG("Read len: %u", rx_data_len);

	if (rx_data_len == 0) {
		LOG_DBG("No response available");
		return 0;
	}

	if (rx_data_len < OPTIGA_DATA_CRTL_FRAME_LEN) {
		LOG_ERR("Frame too small");
		return -EIO;
	}

	u8_t *data_buf = optiga_phy_data_buf(dev, NULL);

	/* Check FCS */
	bool fcs_good = optiga_data_frame_check_fcs(data_buf, rx_data_len);
	/* TODO: handle transmission errors */
	if(!fcs_good) {
		LOG_ERR("FCS error");
		return -EIO;
	}

	/* Frame header parsing */
	u8_t seqctr = optiga_data_get_seqctr(data_buf);

	if (seqctr != OPTIGA_DATA_FCTR_SEQCTR_ACK) {
		LOG_ERR("Packet not acked");
		return -EIO;
	}

	/* check ack matches sent frame */
	u8_t ack_nr = optiga_data_get_ack_nr(data_buf);
	struct optiga_data *driver = dev->driver_data;

	if(driver->data.frame_tx_nr == ack_nr) {
		/* frame nr was acknowledged, increase frame number for next send action */
		driver->data.frame_tx_nr = (driver->data.frame_tx_nr + 1) % 4;
		/* make this ack our last received one */
		driver->data.frame_tx_ack = ack_nr;
	} else if (driver->data.frame_tx_ack == ack_nr) {
		LOG_DBG("Received same ACK twice");
	} else 	{
		// TODO(chr): handle this error
		LOG_ERR("Wrong frame acknowledged");
		return -EIO;
	}

	bool ctrl_frame = optiga_data_is_ctrl_frame(data_buf);
	u16_t frame_len = optiga_data_frame_get_len(data_buf);
	if (ctrl_frame) {
		// TODO(chr): verify against spec that this case can't happen and remove
		LOG_DBG("Control frame");
		__ASSERT(frame_len == 0, "Invalid frame lenght for control frame");
		*data_len = 0;
		return 3;
	}

	LOG_DBG("Data frame");
	/* Ensure frame lenght matches */
	__ASSERT((frame_len + DATA_LINK_OVERHEAD) == rx_data_len, "Invalid frame length");
	*data_len = frame_len;

	/* Acknowledge this frame */
	driver->data.frame_rx_nr = optiga_data_get_frame_nr(data_buf);
	return optiga_send_ack_frame(dev);
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
	driver->data.frame_tx_nr = 0;
	driver->data.frame_tx_ack = 0;
	driver->data.frame_rx_nr = 0;

	LOG_DBG("Data Link init successful");

	return 0;
}

u8_t *optiga_data_packet_buf(struct device *dev, size_t *len)
{
	size_t res_len = 0;
	u8_t *res_buf = optiga_phy_data_buf(dev, &res_len);
	__ASSERT(res_len > DATA_LINK_OVERHEAD, "PHY layer buffer too small");
	res_buf += OPTIGA_DATA_HEADER_LEN;
	res_len -= DATA_LINK_OVERHEAD;

	if(len) {
		*len = res_len;
	}

	return res_buf;
}


