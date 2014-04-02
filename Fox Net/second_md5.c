#include "precomp.h"

UINT32 uint8to32(const UINT8 *v) {
	return (v[3] << 24) | (v[2] << 16) | (v[1] << 8) | v[0];
}

void uint32to8(UINT32 v, UINT8 *d) {
	d[3] = (v >> 24) & 0xff;
	d[2] = (v >> 16) & 0xff;
	d[1] = (v >> 8) & 0xff;
	d[0] = v & 0xff;
}

#define TEA_DELTA 0x9e3779b9

void tea(const UINT8 *k, UINT8 *v, int rounds) {
	UINT32 v0 = uint8to32(v),
		v1 = uint8to32(v + 4),
		key[4];// = { uint8to32(k), uint8to32(k + 4), uint8to32(k + 8), uint8to32(k + 12) };
	int i;
	key[0] = uint8to32(k);
	key[1] = uint8to32(k + 4);
	key[2] = uint8to32(k + 8);
	key[3] = uint8to32(k + 12);

	if (rounds > 0) {
		UINT32 sum = 0;
		for (i = 0; i != rounds; i++) {
			v0 += (v1 ^ sum) + key[sum & 3] + ((v1 << 4) ^ (v1 >> 5));
			sum += TEA_DELTA;
			v1 += (v0 ^ sum) + key[(sum >> 11) & 3] + ((v0 << 4) ^ (v0 >> 5));
		}
	}
	else {
		rounds = -rounds;
		UINT32 sum = TEA_DELTA * rounds;
		for (i = 0; i != rounds; i++) {
			v1 -= (v0 ^ sum) + key[(sum >> 11) & 3] + ((v0 << 4) ^ (v0 >> 5));
			sum -= TEA_DELTA;
			v0 -= (v1 ^ sum) + key[sum & 3] + ((v1 << 4) ^ (v1 >> 5));
		}
	}

	uint32to8(v0, v);
	uint32to8(v1, v + 4);
}

void subn_1209C(const UINT8 *salt, UINT8 *resp2) {
	UINT8 v15[256], tmp, r, tp;
	INT32 i, j;

	for (i = 0; i < 256; i++) {
		v15[i] = (UINT8)i;
	}

	tp = 0;
	for (i = 0; i < 256; i++) {
		tp = (tp + salt[i & 0xf] + v15[i]) & 0xff;
		tmp = v15[i];
		v15[i] = v15[tp];
		v15[tp] = tmp;
	}

	tp = 0;
	for (i = 0; i < 16; i++) {
		j = (i + 1) & 0xff;
		tp = (tp + v15[j]) & 0xff;
		tmp = v15[j];
		v15[j] = v15[tp];
		v15[tp] = tmp;
		r = v15[(tmp + v15[j]) & 0xff];
		resp2[i] ^= r;
	}
}

void do_tyEncrypt(const UINT8 *salt, UINT8 *data) {
	switch (data[0] % 5) {
	case 0:
		tea(salt, data, 16);
		tea(salt, data + 8, 16);
		break;
	case 1:
		tea(salt, data, -16);
		tea(salt, data + 8, -16);
		break;
	case 2:
		tea(salt, data, 32);
		tea(salt, data + 8, 32);
		break;
	case 3:
		tea(salt, data, -32);
		tea(salt, data + 8, -32);
		break;
	case 4:
		subn_1209C(salt, data);
		break;
	}
}
/*
Tianyi's SecondMd5 v2.0
New encrypt digest
*/
void NewChapSecondMd5(UCHAR chap[16])
{
	static UINT8 salt[] = {
		0x03, 0x35, 0xac, 0x6b, 0xe4, 0xc6, 0x4d, 0xe5,
		0xb6, 0xb3, 0xd7, 0x80, 0xe0, 0x80, 0x02, 0x30, 0x12
	};

	do_tyEncrypt(salt, chap);
}
