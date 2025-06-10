/*--------------------------------------------------------------------
 *  AES-CTR DRBG implementation
 *-------------------------------------------------------------------*/
#include "ctr_drbg.h"
#include "AES_ctrdrbg.h"
#include <string.h>
#include <stdio.h>
 /*--------------------------------------------------------------------
  *  내부 유틸
  *-------------------------------------------------------------------*/
static void xor_bytes(uint8_t* d, const uint8_t* s, size_t n)
{
    for (size_t i = 0; i < n; ++i) d[i] ^= s[i];
}

/* big-endian 128-bit counter ++ */
static void inc_V(uint8_t V[CTR_DRBG_VLEN])
{
    for (int i = CTR_DRBG_VLEN - 1; i >= 0; i--)
    {
        if (V[i] == 0xff) V[i] = 0x00;
        else
        {
            V[i]++;
            break;
        }
    }
}

/* AES-256 ECB single-block encrypt */
static void aes256_enc_block(const uint8_t key[CTR_DRBG_KEYLEN],
    const uint8_t in[16], uint8_t out[16])
{
    aes256ctx actx;
    aes256_ecb_keyexp(&actx, key);
    aes256_ecb(out, in, 1, &actx);
    aes256_ctx_release(&actx);
}

/* DRBG Update (SP 800-90A 10.2.1.2) */
static void drbg_update(const uint8_t* provided, CTR_DRBG_CTX* ctx)
{
    uint8_t temp[CTR_DRBG_SEEDLEN];
    size_t ofs = 0;

    for (int i = 0; i < 3; ++i) {
        inc_V(ctx->V);
        aes256_enc_block(ctx->Key, ctx->V, temp + ofs);
        ofs += 16;
    }
    if (provided) xor_bytes(temp, provided, CTR_DRBG_SEEDLEN);

    memcpy(ctx->Key, temp, CTR_DRBG_KEYLEN);
    memcpy(ctx->V, temp + CTR_DRBG_KEYLEN, CTR_DRBG_VLEN);
    /* 민감 데이터 삭제 */
    memset(temp, 0, sizeof temp);
}

/*--------------------------------------------------------------------
 *  API 구현
 *-------------------------------------------------------------------*/
ctr_drbg_err ctr_drbg_instantiate(
    CTR_DRBG_CTX* ctx,
    const uint8_t* entropy, size_t entropy_len,
    const uint8_t* personalization, size_t pers_len)
{
    uint8_t seed[48];
    memcpy(seed, entropy, 48);

    if (personalization && pers_len) {
        size_t n = pers_len > CTR_DRBG_SEEDLEN ? CTR_DRBG_SEEDLEN : pers_len;
        xor_bytes(seed, personalization, n);
    }

    memset(ctx->Key, 0, CTR_DRBG_KEYLEN);
    memset(ctx->V, 0, CTR_DRBG_VLEN);
    drbg_update(seed, ctx);
    ctx->reseed_counter = 1;

    memset(seed, 0, sizeof seed);
    return CTR_DRBG_OK;
}

ctr_drbg_err ctr_drbg_reseed(
    CTR_DRBG_CTX* ctx,
    const uint8_t* entropy, size_t entropy_len,
    const uint8_t* additional, size_t add_len)
{
    if (entropy_len < CTR_DRBG_SEEDLEN)
        return CTR_DRBG_ERR_ENTROPY;

    uint8_t seed[CTR_DRBG_SEEDLEN];
    memcpy(seed, entropy, CTR_DRBG_SEEDLEN);

    if (additional && add_len) {
        size_t n = add_len > CTR_DRBG_SEEDLEN ? CTR_DRBG_SEEDLEN : add_len;
        xor_bytes(seed, additional, n);
    }

    drbg_update(seed, ctx);
    ctx->reseed_counter = 1;

    memset(seed, 0, sizeof seed);
    return CTR_DRBG_OK;
}

ctr_drbg_err ctr_drbg_generate(
    CTR_DRBG_CTX* ctx,
    uint8_t* out, size_t out_len,
    const uint8_t* additional, size_t add_len)
{
    if (out_len > CTR_DRBG_MAX_REQUEST)
        return CTR_DRBG_ERR_REQ_TOO_BIG;

    /* 자동 재시드 검사 */
    if (ctx->reseed_counter > CTR_DRBG_RESEED_INTERVAL)
        return CTR_DRBG_ERR_ENTROPY;   /* 호출자가 reseed 해줘야 함 */

    /* 추가 입력 처리 */
    if (additional && add_len) {
        uint8_t addbuf[CTR_DRBG_SEEDLEN] = { 0 };
        size_t n = add_len > CTR_DRBG_SEEDLEN ? CTR_DRBG_SEEDLEN : add_len;
        memcpy(addbuf, additional, n);
        drbg_update(addbuf, ctx);
        memset(addbuf, 0, sizeof addbuf);
    }

    /* 난수 생성 */
    uint8_t block[16];
    size_t generated = 0;
    while (out_len > 0) {
        inc_V(ctx->V);
        aes256_enc_block(ctx->Key, ctx->V, block);
        if (out_len > 15)
        {
            memcpy(out + generated, block, 16);
            generated += 16;
            out_len -= 16;
        }
        else
        {
            memcpy(out + generated, block, out_len);
            out_len = 0;
        }
    }

    /* post-update, spec: provided_data = additional_input */
    drbg_update(additional && add_len ? additional : NULL, ctx);
    ctx->reseed_counter++;

    /* 블록 메모리 정리 */
    memset(block, 0, sizeof block);
    return CTR_DRBG_OK;
}

void ctr_drbg_clear(CTR_DRBG_CTX* ctx)
{
    if (!ctx) return;
    /* C11 secure-memset 대체 구현 */
#if defined(__STDC_LIB_EXT1__)
    memset_s(ctx, sizeof * ctx, 0, sizeof * ctx);
#else
    volatile uint8_t* p = (volatile uint8_t*)ctx;
    for (size_t i = 0; i < sizeof * ctx; ++i) p[i] = 0;
#endif
}

int DoRNG(int len, uint8_t* rand) {
    CTR_DRBG_CTX drbg;
    /* 실제 구현에서는 HWRNG 등에서 48바이트 엔트로피 획득 */
    uint8_t entropy[48] = {
        0x22, 0xa8, 0x9e, 0xe0, 0xe3, 0x7b, 0x54, 0xea, 0x63, 0x68, 0x63, 0xd9,
        0xfe, 0xd1, 0x08, 0x21, 0xf1, 0x95, 0x2a, 0x42, 0x84, 0x88, 0xd5, 0x28,
        0xec, 0xeb, 0x9d, 0x2e, 0xc6, 0x9d, 0x57, 0x3e, 0xc6, 0x21, 0x62, 0x16,
        0xfb, 0x3e, 0x8f, 0x72, 0xa1, 0x48, 0xa5, 0xad, 0xa9, 0xd6, 0x20, 0xb1
    };

    uint8_t personalization_string[48] = {
        0x95, 0x3c, 0x10, 0xba, 0xdc, 0xbc, 0xd4, 0x5f, 0xb4, 0xe5, 0x47, 0x58,
        0x26, 0x47, 0x7f, 0xc1, 0x37, 0xac, 0x96, 0xa4, 0x9a, 0xd5, 0x00, 0x5f,
        0xb1, 0x4b, 0xda, 0xf6, 0x46, 0x8a, 0xe7, 0xf4, 0x6c, 0x5d, 0x0d, 0xe2,
        0x2d, 0x30, 0x4a, 0xfc, 0x67, 0x98, 0x96, 0x15, 0xad, 0xc2, 0xe9, 0x83
    };

    if (ctr_drbg_instantiate(&drbg, entropy, 48, personalization_string, 48) != CTR_DRBG_OK)
    {
        puts("DRBG 초기화 실패");
        return 1;
    }

    if (ctr_drbg_generate(&drbg, rand, len, NULL, 0) != CTR_DRBG_OK)
    {
        puts("DRBG 생성 실패");
        return 1;
    }

    if (ctr_drbg_generate(&drbg, rand, len, NULL, 0) != CTR_DRBG_OK)
    {
        puts("DRBG 생성 실패");
        return 1;
    }

    for (size_t i = 0; i < len; ++i) printf("%02X", rand[i]);

    printf("\n");

    // for (size_t i = 0; i < 64; ++i) printf("%02X ", rnd[i]);

    ctr_drbg_clear(&drbg);
    return 0;
}

int CTR_DRBG_test() {
    int len = 0;
    printf("Input Length of Random Number : ");
	if (scanf_s("%d", &len) != 1 || len <= 0) {
		puts("Invalid length input.");
		return -1;
	}
    uint8_t* rnd = (uint8_t*)malloc(len);
    DoRNG(len, rnd);
    return 0;
}

int CTR_DRBG_RNG(void* drbg)
{
    unsigned char rnd;
    ctr_drbg_generate((CTR_DRBG_CTX*)drbg, &rnd, 1, NULL, 0);
    return rnd;
}