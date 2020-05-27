/*
 * Copyright (c) 2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _H_TEST_DATA_COMMON_H_
#define _H_TEST_DATA_COMMON_H_

#include <stdint.h>
#include <stddef.h>

/*
// Signature signing key
uint8_t sign_key2[] = {
    0x21, 0xFB, 0x35, 0x5D, 0x5B, 0xAB, 0xB0, 0x45, 0xEB, 0x34, 0xF6, 0x66, 0xF6, 0xA9, 0x3D, 0xD2,
    0x75, 0x14, 0xE0, 0xA1, 0x27, 0xD9, 0xD0, 0x1A, 0x79, 0x4C, 0xC8, 0x1A, 0xE6, 0x47, 0x86, 0x1A
}; */

// Signature verification key
extern const uint8_t verify_test_key[];
extern const size_t verify_test_key_len;

// Signature verification key OPTIGA hack, prefixed with 0x04
extern const uint8_t verify_test_key_optiga[];
extern const size_t verify_test_key_optiga_len;

extern const uint8_t test_hash[];
extern const size_t test_hash_len;

extern const uint8_t test_signature[];
extern const size_t test_signature_len;

extern const uint8_t test_signature_der[];
extern const size_t test_signature_der_len;

extern const uint8_t test_signature_hash[];
extern const size_t test_signature_hash_len;

extern const uint8_t test_certificate[];

extern const uint8_t test_large_data_obj[];
extern const size_t test_large_data_obj_len;

extern const uint8_t test_small_data_obj[];
extern const size_t test_small_data_obj_len;

#endif // _H_TEST_DATA_COMMON_H_
