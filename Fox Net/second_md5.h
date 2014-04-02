#ifndef _SEC_MD5_H
#define _SEC_MD5_H

UINT32 uint8to32(const UINT8 *v);

void uint32to8(UINT32 v, UINT8 *d);

void tea(const UINT8 *k, UINT8 *v, int rounds);

void subn_1209C(const UINT8 *salt, UINT8 *resp2);

void do_tyEncrypt(const UINT8 *salt, UINT8 *data);
/*
Tianyi's SecondMd5 v2.0
New encrypt digest
*/
void NewChapSecondMd5(UCHAR chap[16]);

#endif  //_SEC_MD5_H
