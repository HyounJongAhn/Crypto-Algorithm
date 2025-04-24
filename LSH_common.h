#pragma once
#ifndef _LSH_COMMON_H
#define _LSH_COMMON_H

#include <stdint.h>
typedef uint8_t		u8;			/* 8-bit type */
typedef uint32_t	u32;		/* 32-bit type */
typedef uint64_t	u64;		/* 64-bit type */
typedef uint8_t		Byte;		/* type for raw data */
typedef uint64_t	DataLength;	/* 64-bit word */

//We are on a little-endian platform. On big-endian platforms, comment this:
#ifndef LSH_LITTLE_ENDIAN
#define LSH_LITTLE_ENDIAN
#undef LSH_BIG_ENDIAN
#endif

#if defined _MSC_VER
#include <stdlib.h>
#define bswap64(x) _byteswap_uint64(x)
#define bswap32(x) _byteswap_ulong(x)

//GCC 4.3 or later
#elif defined(__GNUC__) && (__GNUC__*100 + __GNUC_MINOR__*10 >= 430)
#define bswap64(x) __builtin_bswap64(x)
#define bswap32(x) __builtin_bswap32(x) 

//in the other cases
#else
static __inline u64 bswap64(u64 x) {
	x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
	x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
	return (x >> 32) | (x << 32);
}
#define bswap32(x)  (((x)<<24) ^ ((x)>>24)^ (((x)&0xff00)<<8) ^ (((x)&0xff0000)>>8))
#endif

/* bytearray-to-word, word-to-bytearray conversion */
/* can be processed faster on little-endian platforms*/
//x: array of bytes
#ifdef  LSH_BIG_ENDIAN
#define U8TO64_LE(x)            (bswap64(*(u64*)(x)))
#define U8TO32_LE(x)            (bswap32(*(u32*)(x)))
#else 
#define U8TO64_LE(x)            (*(u64*)(x))
#define U8TO32_LE(x)            (*(u32*)(x))
#endif

#define ROL32(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
//#define ROL32(x,n) _rotl(x, n)
//#define ROR32(x,n) _rotr(x, n)

#define ROL64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define ROR64(x,n) (((x)>>(n))|((x)<<(64-(n))))

/* error codes */
#if !(defined(SUCCESS) && defined(FAIL))
#undef SUCCESS
#undef FAIL
#define SUCCESS 0
#define FAIL 1
#endif


#endif