# SPDX-License-Identifier: Apache-2.0

zephyr_library_sources_ifdef(CONFIG_OPTIGA	ifx_i2c/crypto_optiga.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	ifx_i2c/optiga_phy.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	ifx_i2c/optiga_data.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	ifx_i2c/optiga_pre.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	ifx_i2c/optiga_nettran.c)

zephyr_library_sources_ifdef(CONFIG_OPTIGA	trust_m/optiga_trust_m.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	trust_m/ecdsa_utils.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	trust_m/tlv_utils.c)

