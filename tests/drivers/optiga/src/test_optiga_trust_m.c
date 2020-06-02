/*
 * Copyright (c) 2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>
#include <zephyr.h>

#include <drivers/crypto/optiga_trust_m.h>
#include "test_data_common.h"

static struct device *dev = NULL;
static struct optrust_ctx ctx;
static u8_t apdu_buf[OPTRUST_CERT_READ_APDU_SIZE] = {0};


void test_init_trust_m(void)
{
	dev = device_get_binding("trust-m");
	zassert_not_null(dev, "Device not found");
	int res = optrust_init(&ctx, dev, apdu_buf, OPTRUST_CERT_READ_APDU_SIZE);
	zassert_equal(res, 0, "Expected success return code");
}

void test_get_uid(void)
{
	/* Non-unique data from Coprocessor UID, see "Table 38 - Coprocessor UID OPTIGA™ Trust Family" for details */
	static const u8_t expected_id[] = {
		0xCD, /* CIM Identifier */
		0x16, /* Platform Identifier */
		0x33, /* Model Identifier */
		0x82, 0x01, /* ID of ROM mask */
		0x00, 0x1C, 0x00, 0x05, 0x00, 0x00, /* Chip type */
	};

#define TMP_BUF_SIZE 100
	u8_t tmp_buf[TMP_BUF_SIZE] = {0};
	size_t tmp_buf_len = TMP_BUF_SIZE;

	int res = optrust_data_get(&ctx, OPTRUST_OID_COPROCESSOR_UID, 0, tmp_buf, &tmp_buf_len);
	zassert_equal(res, 0, "Expected success return code");

	/* Can only compare the non-unique part here */
	zassert_mem_equal(tmp_buf, expected_id, sizeof(expected_id), "Unexpected chip");
#undef TMP_BUF_SIZE
}

void test_data_object_large(void)
{
	u8_t tmp_buf[OPTRUST_DATA_OBJECT_TYPE2_LEN] = {0};
	size_t tmp_buf_len = OPTRUST_DATA_OBJECT_TYPE2_LEN;

	/* Fill a data object with test data */
	int res = optrust_data_set(&ctx, OPTRUST_OID_DATA_OBJECT_17, true, 0, test_large_data_obj, test_large_data_obj_len);
	zassert_equal(res, 0, "Writing test data failed");

	/* Read back test data */
	res = optrust_data_get(&ctx, OPTRUST_OID_DATA_OBJECT_17, 0, tmp_buf, &tmp_buf_len);
	zassert_equal(res, 0, "Reading test data failed");
	zassert_equal(tmp_buf_len, test_large_data_obj_len, "Read back size is different");
	zassert_mem_equal(tmp_buf, test_large_data_obj, tmp_buf_len, "Data doesn't match");
}

void test_data_object_small(void)
{
	u8_t tmp_buf[OPTRUST_DATA_OBJECT_TYPE3_LEN] = {0};
	size_t tmp_buf_len = OPTRUST_DATA_OBJECT_TYPE3_LEN;

	/* Fill a data object with test data */
	int res = optrust_data_set(&ctx, OPTRUST_OID_DATA_OBJECT_1, true, 0, test_small_data_obj, test_small_data_obj_len);
	zassert_equal(res, 0, "Writing test data failed");

	/* Read back test data */
	res = optrust_data_get(&ctx, OPTRUST_OID_DATA_OBJECT_1, 0, tmp_buf, &tmp_buf_len);
	zassert_equal(res, 0, "Reading test data failed");
	zassert_equal(tmp_buf_len, test_small_data_obj_len, "Read back size is different");
	zassert_mem_equal(tmp_buf, test_small_data_obj, tmp_buf_len, "Data doesn't match");
}

void test_optiga_trust_m_main(void)
{
	ztest_test_suite(optiga_trust_m_tests,
		ztest_unit_test(test_init_trust_m),
		ztest_unit_test(test_get_uid),
		ztest_unit_test(test_data_object_small),
		ztest_unit_test(test_data_object_large)
	);

	ztest_run_test_suite(optiga_trust_m_tests);
}
