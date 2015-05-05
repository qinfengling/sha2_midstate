/*
 * Bitcoin midstate demo
 * shame with some code from cgminer.
 * Copyright (C) 2015 Mikeqin <Fengling.Qin@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdio.h>
#include <string.h>
#include "sha2.h"

static const int hex2bin_tbl[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/* Does the reverse of bin2hex but does not allocate any ram */
static unsigned char hex2bin(unsigned char *p, const unsigned char *hexstr, unsigned int len)
{
	int nibble1, nibble2;
	unsigned char idx;
	unsigned char ret = 0;

	while (*hexstr && len) {
		if ((!hexstr[1])) {
			return ret;
		}

		idx = *hexstr++;
		nibble1 = hex2bin_tbl[idx];
		idx = *hexstr++;
		nibble2 = hex2bin_tbl[idx];

		if (((nibble1 < 0) || (nibble2 < 0))) {
			return ret;
		}

		*p++ = (((unsigned char)nibble1) << 4) | ((unsigned char)nibble2);
		--len;
	}

	if (len == 0 && *hexstr == 0)
		ret = 1;
	return ret;
}

static void revbuf(unsigned char *buf, uint32_t len)
{
	uint8_t tmp;
	uint32_t i;

	for (i = 0; i < len / 2; i++) {
		tmp = buf[len - 1 - i];
		buf[len - 1 - i] = buf[i];
		buf[i] = tmp;
	}
}

static void convendian(unsigned char *buf, uint32_t len)
{
	uint32_t tmp;
	uint32_t i;

	if (len % 4)
		return;

	for (i = 0; i < len; i+=4) {
		memcpy(&tmp, buf + i, 4);
		tmp = (tmp >> 24) | (tmp << 24) | ((tmp >> 8) & 0xff00) | ((tmp << 8) & 0xff0000);
		memcpy(buf + i, &tmp, 4);
	}
}

int main(void)
{
	/* header
	 * 00000003b968b96fd5c2e94facad8296e7e8a9a87fa565810108fb760000000000000000cb59ccf140d92666713f71b56cd2702b60383c8e9f9685e8fd6fa7f8
	 * d22dfc5955372b8b181717f000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000
	 *
	 * icarus format : midstate (32 bytes) + reserved (20 bytes) + data (12 bytes)
	 * 62462b5ee07afe103e86dd9eef330045a12e7215f5fecb6762ac8ad7b9829f8d0000000000000000000000000000000000000000f01717188b2b375559fc2dd2
	 * nonce: 5e2199c8
	 */
	unsigned char strbuf[] = "030000006fb968b94fe9c2d59682adaca8a9e8e78165a57f76fb08010000000000000000f1cc59cb6626d940b5713f712b70d26c8e3c3860e885969ff8a76ffd";
	unsigned char strdat[] = "59fc2dd28b2b3755f01717185e2199c8";
	unsigned char stricamid[] = "62462b5ee07afe103e86dd9eef330045a12e7215f5fecb6762ac8ad7b9829f8d";
	unsigned char stricadat[] = "f01717188b2b375559fc2dd25e2199c8";
	uint8_t buf[64], dat[16];
	uint8_t ica_mid[32], ica_dat[16];
	uint32_t temp_h[8], i;
	sha256_ctx ctx;
	unsigned char digest[32];

	/* method 1: calculate dsha256 from block header */
	hex2bin(buf, strbuf, 64);
	hex2bin(dat, strdat, 16);

	sha256_init(&ctx, NULL);
	sha256_update(&ctx, buf, 64);

	printf("init h:");
	for (i = 0; i < 8; i++)
		printf("%04x", ctx.h[i]);
	printf("\n");

	sha256_update(&ctx, dat, 16);
	sha256_final(&ctx, digest);

	sha256_init(&ctx, NULL);
	sha256_update(&ctx, digest, 32);
	sha256_final(&ctx, digest);
	printf("dbhash:");
	for (i = 0; i < 32; i++)
		printf("%02x", digest[i]);
	printf("\n");

	/* method 2: calculate dsha256 from midstate & data (icarus format) */
	hex2bin(ica_mid, stricamid, 32);
	hex2bin(ica_dat, stricadat, 16);

	revbuf(ica_mid, 32);
	revbuf(ica_dat, 12);
	convendian(ica_dat, 12);
	for (i = 0; i < 32; i+=4)
		temp_h[i / 4] = ica_mid[i] | (ica_mid[i + 1] << 8) | (ica_mid[i + 2] << 16) | (ica_mid[i + 3] << 24);

	printf("init h:");
	for (i = 0; i < 8; i++)
		printf("%04x", temp_h[i]);
	printf("\n");

	sha256_init(&ctx, temp_h);
	ctx.tot_len = 64;
	sha256_update(&ctx, ica_dat, 16);
	sha256_final(&ctx, digest);

	sha256_init(&ctx, NULL);
	sha256_update(&ctx, digest, 32);
	sha256_final(&ctx, digest);
	printf("dbhash:");
	for (i = 0; i < 32; i++)
		printf("%02x", digest[i]);
	printf("\n");

	return 0;
}

