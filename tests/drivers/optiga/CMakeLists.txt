# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr HINTS $ENV{ZEPHYR_BASE})
project(optiga_tests)

target_sources(app PRIVATE src/main.c src/test_optiga_apdu.c src/test_optiga_trust_m.c)
