# SPDX-License-Identifier: Apache-2.0

zephyr_library_sources_ifdef(CONFIG_OPTIGA	crypto_optiga.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	optiga_phy.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	optiga_data.c)
zephyr_library_sources_ifdef(CONFIG_OPTIGA	optiga_nettran.c)
