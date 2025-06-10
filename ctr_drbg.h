#ifndef CTR_DRBG_H
#define CTR_DRBG_H
/*---------------------------------------------------------------------
 * AES-CTR DRBG (NIST SP 800-90A Rev.1, “CTR_DRBG without DF”)
 *  * AES-256  + 128-bit counter
 *  * AdditionalInput / Personalization / Reseed 지원
 *  * 자동 re-seed(2^24 block ≒ 16 MiB) / 요청 길이 검사
 *  * 스레드 안전 : 전역 대신 컨텍스트 포인터 사용
 *--------------------------------------------------------------------*/
#include <stddef.h>
#include <stdint.h>
#include "AES_ctrdrbg.h"

#define CTR_DRBG_KEYLEN        32          /* 256-bit key            */
#define CTR_DRBG_VLEN          16          /* 128-bit counter        */
#define CTR_DRBG_SEEDLEN       (CTR_DRBG_KEYLEN + CTR_DRBG_VLEN)
#define CTR_DRBG_MAX_REQUEST   65536       /* ≤ 2^19 bits per spec   */
#define CTR_DRBG_RESEED_INTERVAL  (1ULL<<24) /* 16 MiB 생성마다 reseed */

typedef enum {
    CTR_DRBG_OK = 0,
    CTR_DRBG_ERR_INPUTLEN = -1,
    CTR_DRBG_ERR_REQ_TOO_BIG = -2,
    CTR_DRBG_ERR_ENTROPY = -3,
} ctr_drbg_err;

/* DRBG state */
typedef struct {
    uint8_t Key[CTR_DRBG_KEYLEN];
    uint8_t V[CTR_DRBG_VLEN];
    uint64_t reseed_counter;
} CTR_DRBG_CTX;

/* API ----------------------------------------------------------------*/
ctr_drbg_err ctr_drbg_instantiate(
    CTR_DRBG_CTX* ctx,
    const uint8_t* entropy, size_t entropy_len,
    const uint8_t* personalization, size_t pers_len);

ctr_drbg_err ctr_drbg_reseed(
    CTR_DRBG_CTX* ctx,
    const uint8_t* entropy, size_t entropy_len,
    const uint8_t* additional, size_t add_len);

ctr_drbg_err ctr_drbg_generate(
    CTR_DRBG_CTX* ctx,
    uint8_t* out, size_t out_len,
    const uint8_t* additional, size_t add_len);

void ctr_drbg_clear(CTR_DRBG_CTX* ctx);
int DoRNG(int len, uint8_t* rand);
int CTR_DRBG_test();
int CTR_DRBG_RNG(void* drbg);
#endif /* CTR_DRBG_H */