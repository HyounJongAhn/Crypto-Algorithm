/* sha512.h */
#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_BLOCK_SIZE   128
#define SHA512_DIGEST_SIZE   64

typedef struct {
    uint64_t h[8];         /* �ؽ� ���°� */
    uint64_t w[16];        /* 1024��Ʈ ûũ �ӽ� ����� (16��64��Ʈ ����) */
    uint64_t lengthLow;    /* ó���� ��ü ��Ʈ ���� ���� 64��Ʈ */
    uint64_t lengthHigh;   /* ó���� ��ü ��Ʈ ���� ���� 64��Ʈ */
    uint8_t  chunkSize;    /* ctx->w ����Ʈ ������ ä���� ũ�� */
} SHA512_CTX;

/* SHA-512 �⺻ API */
void SHA512_Init(SHA512_CTX* ctx);
void SHA512_Update(SHA512_CTX* ctx, const void* data, size_t len);
void SHA512_Final(SHA512_CTX* ctx, uint8_t hash[SHA512_DIGEST_SIZE]);

/* HMAC-SHA512 API */
void SHA512_HMAC_Init(SHA512_CTX* ctx, const void* key, size_t keyLen);
void SHA512_HMAC_Update(SHA512_CTX* ctx, const void* data, size_t len);
void SHA512_HMAC_Final(SHA512_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA512_DIGEST_SIZE]);

#endif /* SHA512_H */
