/*
 * Copyright (c) 2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>
#include <zephyr.h>

extern void test_optiga_apdu_main(void);
extern void test_optiga_trust_m_main(void);

void test_main(void)
{
	test_optiga_apdu_main();
	test_optiga_trust_m_main();
}
