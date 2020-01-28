/*
 * Copyright (c) 2019 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <logging/log_ctrl.h>
#include <logging/log.h>
LOG_MODULE_REGISTER(test);

#include <zephyr.h>
#include "helpers.h"

#include <drivers/crypto/optiga.h>


/** return types of a testcase */
typedef enum
{
    /** The test passed */
    PASS = 0,
    /** The test failed */
    FAIL = 1,
} test_ret_t;

/**
 * @brief Function signature of a test function. A test function should test
 *        exactly one thing.
 * @returns PASS on a passed test or FAIL when the test failed.
 */
typedef test_ret_t (*test_function_t)(void);

// Maximum length of a test case name
#define TEST_INTERFACE_NAME_LEN 30

// this converts to string
#define STR_(X) #X

// this makes sure the argument is expanded before converting to string
#define STR(X) STR_(X)

#define RES_STR(result) (((result) == PASS) ? "PASS" : "FAIL")
#define RES_FMT "%s : %-" STR(TEST_INTERFACE_NAME_LEN) "s time: %4d.%03d ms"

// Timer runs at 1MHz
#define TIMER_FREQ (1000*1000)
#define TO_MS(x) ((x)/(TIMER_FREQ/1000))
#define TO_US(x) ((x)/(TIMER_FREQ/(1000*1000)))

/**
 * @brief Runs a test function and measures the runtime
 * @param func Test function to run
 * @param name Name to print with the test result
 */
test_ret_t run_timed(test_function_t func, const char* name)
{
	/* capture initial time stamp */
	u32_t start_time = k_cycle_get_32();

	/* do work */
	test_ret_t res = func();

	/* capture final time stamp */
	u32_t stop_time = k_cycle_get_32();

	/* compute how long the work took (assumes no counter rollover) */
	u32_t cycles_spent = stop_time - start_time;
	u32_t nanoseconds_spent = SYS_CLOCK_HW_CYCLES_TO_NS(cycles_spent);
	u32_t us_passed = nanoseconds_spent/1000;
	u32_t ms = TO_MS(us_passed);
	u32_t us = TO_US(us_passed) % 1000;
	LOG_INF(RES_FMT, RES_STR(res), name, ms, us);
	/* Let logger process */
	k_sleep(50);

	return res;
}


test_ret_t test_fcs(void)
{
	/* Test case for FCS */
	const u8_t fcs_test_res[] = {0xa0, 0x00, 0x00, 0x0f, 0xd7};
	u8_t fcs_test_vec2[] = {0xa0, 0x00, 0x00, 0x00, 0x00};
	optiga_data_frame_set_fcs(fcs_test_vec2, 3);

	int equal = equals(fcs_test_res, sizeof(fcs_test_res), fcs_test_vec2, sizeof(fcs_test_vec2));

	return equal ? PASS : FAIL;
}

extern struct device *dev;

test_ret_t phy_test(void)
{
#define DATA_REG_LEN_SIZE 2
	static const u8_t data_reg_len_test_val[DATA_REG_LEN_SIZE] = {0x00, 0x40};
	u8_t data_reg_len_reg[DATA_REG_LEN_SIZE] = {0};
	int res = optiga_reg_read(dev, 0x81, data_reg_len_reg, DATA_REG_LEN_SIZE);
	if (res != 0) {
		LOG_INF("Failed to read data reg len register");
		return FAIL;
	}

	LOG_HEXDUMP_INF(data_reg_len_reg, DATA_REG_LEN_SIZE, "Read data reg len:");

	size_t frame_buf_len = 0;
	u8_t *frame_buf = optiga_phy_frame_buf(dev, &frame_buf_len);

	if (frame_buf_len < DATA_REG_LEN_SIZE) {
		return FAIL;
	}

	memcpy(frame_buf, data_reg_len_test_val, DATA_REG_LEN_SIZE);

	res = optiga_reg_write(dev, 0x81, DATA_REG_LEN_SIZE);
	if (res != 0) {
		LOG_INF("Failed to write data reg len register");
		return FAIL;
	}

	memset(data_reg_len_reg, 0, DATA_REG_LEN_SIZE);

	res = optiga_reg_read(dev, 0x81, data_reg_len_reg, DATA_REG_LEN_SIZE);
	if (res != 0) {
		LOG_INF("Failed to read data reg len register");
		return FAIL;
	}

	LOG_HEXDUMP_INF(data_reg_len_reg, DATA_REG_LEN_SIZE, "Read data reg len:");

	/* Should be the written value */
	if(!equals(data_reg_len_test_val, DATA_REG_LEN_SIZE,
		data_reg_len_reg, DATA_REG_LEN_SIZE)) {
		return FAIL;
	}

	/* reset and check data_reg_len if it worked */
	res =  optiga_soft_reset(dev);
	if (res != 0) {
		LOG_INF("Failed to perform soft reset");
		return FAIL;
	}

	memset(data_reg_len_reg, 0, DATA_REG_LEN_SIZE);

	res = optiga_reg_read(dev, 0x81, data_reg_len_reg, DATA_REG_LEN_SIZE);
	if (res != 0) {
		LOG_INF("Failed to read data reg len register");
		return FAIL;
	}

	/* Should now be the initial value again */
	if(equals(data_reg_len_test_val, DATA_REG_LEN_SIZE,
		data_reg_len_reg, DATA_REG_LEN_SIZE)) {
		return FAIL;
	}

	LOG_HEXDUMP_INF(data_reg_len_reg, DATA_REG_LEN_SIZE, "Read data reg len:");

	return PASS;
#undef DATA_REG_LEN_SIZE
}

#define TMP_BUF_SIZE 1024
static u8_t tmp_buf[TMP_BUF_SIZE] = {0};
static size_t tmp_buf_len = TMP_BUF_SIZE;

test_ret_t get_data_object_small(void)
{
	const u8_t get_data_object_apdu[] = {
		0x81, /* command code */
		0x00, /* param, read data */
		0x00, 0x06, /* Length */
		0xF1, 0xE0, /* OID */
		0x00, 0x00, /* Offset */
		0x00, 0x10,
	};

	int res = optiga_nettran_send_apdu(dev,
		get_data_object_apdu,
		sizeof(get_data_object_apdu));

	if(res != 0) {
		return FAIL;
	}

	k_sleep(500);

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);

	return res ? FAIL : PASS;
}

test_ret_t set_data_object_small(void)
{
	const u8_t set_data_object_apdu[] = {
		0x82, /* command code */
		0x40, /* param, erease & write data */
		0x00, 20, /* Length */
		0xF1, 0xE0, /* OID */
		0x00, 0x00, /* Offset */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		};

	LOG_INF("Set DO:");
	int res = optiga_nettran_send_apdu(dev,
		set_data_object_apdu,
		sizeof(set_data_object_apdu));

	LOG_INF("APDU send result: %d", res);

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	if (res != 0) {
		LOG_INF("Failed to read set DO APDU response");
		return FAIL;
	}

	LOG_HEXDUMP_INF(tmp_buf, tmp_buf_len, "Set DO response:");

	return res ? FAIL : PASS;

}

test_ret_t set_data_object(void)
{
	const u8_t set_data_object_apdu[] = {
		0x82, /* command code */
		0x40, /* param, erease & write data */
		0x02, 0x04, /* Length */
		0xF1, 0xE0, /* OID */
		0x00, 0x00, /* Offset */
		0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, /* 16 bytes data */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xEF, /* 16 bytes data */
														/* 512 bytes total */
		};

	int res = optiga_nettran_send_apdu(dev,
		set_data_object_apdu,
		sizeof(set_data_object_apdu));

	if(res != 0) {
		return FAIL;
	}

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);

	return res ? FAIL : PASS;
}

test_ret_t get_data_object(void)
{
	const u8_t get_data_object_apdu[] = {
		0x81, /* command code */
		0x00, /* param, read data */
		0x00, 0x02, /* Length */
		0xF1, 0xE0, /* OID */
	};

	LOG_INF("Get DO:");
	int res = optiga_nettran_send_apdu(dev,
		get_data_object_apdu,
		sizeof(get_data_object_apdu));

	if(res != 0) {
		return FAIL;
	}

	tmp_buf_len = TMP_BUF_SIZE;

	res = optiga_nettran_recv_apdu(dev, tmp_buf, &tmp_buf_len);
	return res ? FAIL : PASS;
}

test_ret_t get_data_object_queued(void)
{
	const u8_t get_data_object_apdu[] = {
		0x81, /* command code */
		0x00, /* param, read data */
		0x00, 0x02, /* Length */
		0xF1, 0xE0, /* OID */
	};

	struct optiga_apdu get_do_txrx = {
		.tx_buf = get_data_object_apdu,
		.tx_len = sizeof(get_data_object_apdu),
		.rx_buf = tmp_buf,
		.rx_len = TMP_BUF_SIZE,
	};

	optiga_enqueue_apdu(dev, &get_do_txrx);

	struct k_poll_event events[1] = {
        K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SIGNAL,
                                 K_POLL_MODE_NOTIFY_ONLY,
                                 &get_do_txrx.finished),
	};

	k_poll(events, 1, K_FOREVER);

	int result_code = events[0].signal->result;

	return result_code ? FAIL : PASS;
}


void run_tests()
{
	int failed_cnt = 0;

	/* Tests without Trust X/M lib */
	failed_cnt += run_timed(test_fcs, "FCS Test");
	failed_cnt += run_timed(phy_test, "PHY Test");
	/* Need to reset all protocol layers because PHY Test can mess them up */
	optiga_reset(dev);

	failed_cnt += run_timed(set_data_object_small, "APDU Set DO small");
	failed_cnt += run_timed(get_data_object_small, "APDU Get DO small");

	failed_cnt += run_timed(set_data_object, "APDU Set DO");
	failed_cnt += run_timed(get_data_object_small, "APDU Get DO");
	failed_cnt += run_timed(get_data_object_small, "APDU Get DO queued");

	if (failed_cnt > 0) {
		LOG_ERR("Failed test count: %d", failed_cnt);
	}
	__ASSERT(failed_cnt == 0, "None of these tests should fail");
}