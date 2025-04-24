/* sha224.h */
#ifndef SHA224_H
#define SHA224_H

#include <stddef.h>
#include <stdint.h>

#define SHA224_DIGEST_SIZE 28
#define SHA224_BLOCK_SIZE 64

typedef struct {
    uint32_t h[8];         /* 해시 상태 */
    uint32_t w[16];        /* 한 블록(512비트) 임시 저장소 */
    uint64_t length;       /* 처리된 전체 비트 길이 */
    uint8_t  chunkSize;    /* 현재 버퍼에 남은 바이트 수 */
} SHA224_CTX;

/* 기본 SHA‑224 */
void SHA224_Init(SHA224_CTX* ctx);
void SHA224_Update(SHA224_CTX* ctx, const void* data, size_t len);
void SHA224_Final(SHA224_CTX* ctx, uint8_t hash[SHA224_DIGEST_SIZE]);

/* HMAC‑SHA224 */
void SHA224_HMAC_Init(SHA224_CTX* ctx, const void* key, size_t keyLen);
void SHA224_HMAC_Update(SHA224_CTX* ctx, const void* data, size_t len);
void SHA224_HMAC_Final(SHA224_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA224_DIGEST_SIZE]);

#endif /* SHA224_H */
