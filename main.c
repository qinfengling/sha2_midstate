#include <stdio.h>
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

int main(void)
{
	unsigned char strbuf[] = "8d9f82b9d78aac6267cbfef515722ea1450033ef9edd863e10fe7ae05e2b4662d22dfc5955372b8b181717f0";
	uint8_t buf[44];
	unsigned int per_a[3], per_b[3];

	hex2bin(buf, strbuf, 44);
	sha256_loc(buf, per_a, per_b);
	printf("sha256_loc:\n");
	printf("%08x-%08x-%08x\n", per_a[0], per_a[1], per_a[2]);
	printf("%08x-%08x-%08x\n", per_b[0], per_b[1], per_b[2]);
	sha256_loc1(buf, per_a, per_b);
	printf("sha256_loc1:\n");
	printf("%08x-%08x-%08x\n", per_a[0], per_a[1], per_a[2]);
	printf("%08x-%08x-%08x\n", per_b[0], per_b[1], per_b[2]);
}
