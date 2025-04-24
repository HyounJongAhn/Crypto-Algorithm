/* sha256.h */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t h[8];        /* 해시 상태 */
    uint32_t w[16];       /* 512비트 청크 임시 저장소 (16×32비트 워드) */
    uint64_t length;      /* 처리된 전체 비트 길이 */
    uint8_t  chunkSize;   /* 현재 ctx->w에 남은 바이트 수 */
} SHA256_CTX;

/* SHA-256 기본 함수 */
void SHA256_Init(SHA256_CTX* ctx);
void SHA256_Update(SHA256_CTX* ctx, const void* data, size_t len);
void SHA256_Final(SHA256_CTX* ctx, uint8_t hash[SHA256_DIGEST_SIZE]);

/* HMAC-SHA256 함수 */
void SHA256_HMAC_Init(SHA256_CTX* ctx, const void* key, size_t keyLen);
void SHA256_HMAC_Update(SHA256_CTX* ctx, const void* data, size_t len);
void SHA256_HMAC_Final(SHA256_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */
