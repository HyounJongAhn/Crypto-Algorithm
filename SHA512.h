/* sha512.h */
#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_BLOCK_SIZE   128
#define SHA512_DIGEST_SIZE   64

typedef struct {
    uint64_t h[8];         /* 해시 상태값 */
    uint64_t w[16];        /* 1024비트 청크 임시 저장소 (16×64비트 워드) */
    uint64_t lengthLow;    /* 처리된 전체 비트 길이 하위 64비트 */
    uint64_t lengthHigh;   /* 처리된 전체 비트 길이 상위 64비트 */
    uint8_t  chunkSize;    /* ctx->w 바이트 단위로 채워진 크기 */
} SHA512_CTX;

/* SHA-512 기본 API */
void SHA512_Init(SHA512_CTX* ctx);
void SHA512_Update(SHA512_CTX* ctx, const void* data, size_t len);
void SHA512_Final(SHA512_CTX* ctx, uint8_t hash[SHA512_DIGEST_SIZE]);

/* HMAC-SHA512 API */
void SHA512_HMAC_Init(SHA512_CTX* ctx, const void* key, size_t keyLen);
void SHA512_HMAC_Update(SHA512_CTX* ctx, const void* data, size_t len);
void SHA512_HMAC_Final(SHA512_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA512_DIGEST_SIZE]);

#endif /* SHA512_H */
