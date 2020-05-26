/*
 * Copyright (c) 2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>
#include <zephyr.h>

#include <drivers/crypto/optiga_trust_m.h>

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

void test_optiga_trust_m_main(void)
{
	ztest_test_suite(optiga_trust_m_tests,
		ztest_unit_test(test_init_trust_m)
	);

	ztest_run_test_suite(optiga_trust_m_tests);
}
