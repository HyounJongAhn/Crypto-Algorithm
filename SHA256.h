/* sha256.h */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t h[8];        /* �ؽ� ���� */
    uint32_t w[16];       /* 512��Ʈ ûũ �ӽ� ����� (16��32��Ʈ ����) */
    uint64_t length;      /* ó���� ��ü ��Ʈ ���� */
    uint8_t  chunkSize;   /* ���� ctx->w�� ���� ����Ʈ �� */
} SHA256_CTX;

/* SHA-256 �⺻ �Լ� */
void SHA256_Init(SHA256_CTX* ctx);
void SHA256_Update(SHA256_CTX* ctx, const void* data, size_t len);
void SHA256_Final(SHA256_CTX* ctx, uint8_t hash[SHA256_DIGEST_SIZE]);

/* HMAC-SHA256 �Լ� */
void SHA256_HMAC_Init(SHA256_CTX* ctx, const void* key, size_t keyLen);
void SHA256_HMAC_Update(SHA256_CTX* ctx, const void* data, size_t len);
void SHA256_HMAC_Final(SHA256_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */
