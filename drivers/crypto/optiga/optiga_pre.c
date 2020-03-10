/*
 * Copyright (c) 2019-2020 Infineon Technologies AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crypto_optiga.h"

#include "optiga_pre.h"
#include "optiga_nettran.h"

#include <sys/byteorder.h>

#include <mbedtls/md.h>
#include <mbedtls/ccm.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(optiga_pre);


// ported from ssl_tls.c, maybe replace with export from mbedtls?
static int tls_prf_sha256( const u8_t *secret, size_t slen,
                           const char *label,
                           const u8_t *random, size_t rlen,
                           u8_t *dstbuf, size_t dlen )
{
	size_t nb;
	size_t i, j, k, md_len;
	u8_t tmp[128];
	u8_t h_i[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info;
	mbedtls_md_context_t md_ctx;
	int ret;

	mbedtls_md_init( &md_ctx );

	md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );

	if (md_info == NULL) {
		return -EINVAL;
	}

	md_len = mbedtls_md_get_size( md_info );

	if ( sizeof( tmp ) < md_len + strlen( label ) + rlen ) {
		return -EINVAL;
	}

	nb = strlen( label );
	memcpy( tmp + md_len, label, nb );
	memcpy( tmp + md_len + nb, random, rlen );
	nb += rlen;

	/*
	* Compute P_<hash>(secret, label + random)[0..dlen]
	*/

	ret = mbedtls_md_setup( &md_ctx, md_info, 1 );

	if (ret != 0) {
		return -EINVAL;
	}

	mbedtls_md_hmac_starts( &md_ctx, secret, slen );
	mbedtls_md_hmac_update( &md_ctx, tmp + md_len, nb );
	mbedtls_md_hmac_finish( &md_ctx, tmp );

	for( i = 0; i < dlen; i += md_len )
	{
		mbedtls_md_hmac_reset ( &md_ctx );
		mbedtls_md_hmac_update( &md_ctx, tmp, md_len + nb );
		mbedtls_md_hmac_finish( &md_ctx, h_i );

		mbedtls_md_hmac_reset ( &md_ctx );
		mbedtls_md_hmac_update( &md_ctx, tmp, md_len );
		mbedtls_md_hmac_finish( &md_ctx, tmp );

		k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

		for( j = 0; j < k; j++ ) {
			dstbuf[i + j]  = h_i[j];
		}
	}

	mbedtls_md_free( &md_ctx );

	mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
	mbedtls_platform_zeroize( h_i, sizeof( h_i ) );

	return 0;
}

int optiga_pre_init(struct device *dev) {
	struct optiga_data *driver = dev->driver_data;

	driver->present.enabled = false;

	return 0;
}

/*
 * @brief Sets the shared secrect and derives session keys
 * @param dev Device to operate on
 * @param ssec Pointer to shared secret, NULL invalidates all session data
 * @param ssec_len Length of ssec, 0 invalidates all session data
 */
int optiga_pre_set_shared_secret(struct device *dev, const u8_t *ssec, size_t ssec_len)
{

}

int optiga_pre_recv_apdu(struct device *dev, size_t *data_len)
{
	// TODO(chr): implement
	return -ENOTSUP;
}

int optiga_pre_send_apdu(struct device *dev, size_t len)
{
	// TODO(chr): implement
	return -ENOTSUP;
}

u8_t *optiga_pre_packet_buf(struct device *dev, size_t *len)
{
	struct optiga_data *driver = dev->driver_data;
	size_t res_len = 0;
	u8_t* res_buf = optiga_data_packet_buf(dev, &res_len);

	if (driver->present.enabled) {
		// TODO(chr): implement
	}

	*len = res_len;
	return res_buf;
}
