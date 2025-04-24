/* sha384.h */
#ifndef SHA384_H
#define SHA384_H

#include <stddef.h>
#include <stdint.h>

#define SHA384_BLOCK_SIZE   128
#define SHA384_DIGEST_SIZE   48

typedef struct {
    uint64_t h[8];         /* 해시 상태값 */
    uint64_t w[16];        /* 1024비트 청크 임시 저장소 */
    uint64_t lengthLow;    /* 처리된 전체 비트 길이(하위 64비트) */
    uint64_t lengthHigh;   /* 처리된 전체 비트 길이(상위 64비트) */
    uint8_t  chunkSize;    /* ctx->w 바이트 단위로 채워진 크기 */
} SHA384_CTX;

/* SHA-384 기본 API */
void SHA384_Init(SHA384_CTX* ctx);
void SHA384_Update(SHA384_CTX* ctx, const void* data, size_t len);
void SHA384_Final(SHA384_CTX* ctx, uint8_t hash[SHA384_DIGEST_SIZE]);

/* HMAC-SHA384 API */
void SHA384_HMAC_Init(SHA384_CTX* ctx, const void* key, size_t keyLen);
void SHA384_HMAC_Update(SHA384_CTX* ctx, const void* data, size_t len);
void SHA384_HMAC_Final(SHA384_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA384_DIGEST_SIZE]);

#endif /* SHA384_H */
