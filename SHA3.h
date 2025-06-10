#pragma once
#ifndef _SHA3_H_
#define _SHA3_H_


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define KECCAK_SPONGE_BIT		1600
#define KECCAK_ROUND			24
#define KECCAK_STATE_SIZE		200

#define KECCAK_SHA3_224			224
#define KECCAK_SHA3_256			256
#define KECCAK_SHA3_384			384
#define KECCAK_SHA3_512			512
#define KECCAK_SHAKE128			128
#define KECCAK_SHAKE256			256

#define KECCAK_SHA3_SUFFIX		0x06
#define KECCAK_SHAKE_SUFFIX		0x1F



#ifdef __cplusplus
extern "C"
{
#endif



	int sha3_hash(uint8_t* output, int outLen, uint8_t* input, int inLen, int bitSize, int useSHAKE);
	void sha3test();
}
#else

#endif
