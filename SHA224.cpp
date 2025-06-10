#include "sha224.h"
#include <string.h>

#define BE32TOH(x) ( \
    (((x) & 0xFF000000u) >> 24) | \
    (((x) & 0x00FF0000u) >>  8) | \
    (((x) & 0x0000FF00u) <<  8) | \
    (((x) & 0x000000FFu) << 24) )
#define HTOBE32(x) BE32TOH(x)

#define ROTR(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)   ((x) >> (n))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)   (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define BSIG1(x)   (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SSIG0(x)   (ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3))
#define SSIG1(x)   (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void processChunk(SHA224_CTX* ctx)
{
    uint32_t w[64];

    for (int i = 0; i < 16; ++i)
        w[i] = BE32TOH(ctx->w[i]);
    for (int i = 16; i < 64; ++i)
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
    uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

void SHA224_Init(SHA224_CTX* ctx)
{
    ctx->h[0] = 0xc1059ed8;
    ctx->h[1] = 0x367cd507;
    ctx->h[2] = 0x3070dd17;
    ctx->h[3] = 0xf70e5939;
    ctx->h[4] = 0xffc00b31;
    ctx->h[5] = 0x68581511;
    ctx->h[6] = 0x64f98fa7;
    ctx->h[7] = 0xbefa4fa4;
    ctx->length = 0;
    ctx->chunkSize = 0;
}

void SHA224_Update(SHA224_CTX* ctx, const void* data, size_t len)
{
    ctx->length += ((uint64_t)len) << 3;
    const uint8_t* d = (const uint8_t*)data;
    while (len > 0) {
        size_t take = SHA224_BLOCK_SIZE - ctx->chunkSize;
        if (take > len) take = len;
        memcpy(((uint8_t*)ctx->w) + ctx->chunkSize, d, take);
        ctx->chunkSize += take;
        d += take;
        len -= take;
        if (ctx->chunkSize == SHA224_BLOCK_SIZE) {
            processChunk(ctx);
            ctx->chunkSize = 0;
        }
    }
}

void SHA224_Final(SHA224_CTX* ctx, uint8_t hash[SHA224_DIGEST_SIZE])
{
    uint8_t* wbytes = (uint8_t*)ctx->w;
    if (ctx->chunkSize <= SHA224_BLOCK_SIZE - 9) {
        wbytes[ctx->chunkSize] = 0x80;
        memset(wbytes + ctx->chunkSize + 1, 0x00,
            SHA224_BLOCK_SIZE - 8 - (ctx->chunkSize + 1));
    }
    else {
        wbytes[ctx->chunkSize] = 0x80;
        memset(wbytes + ctx->chunkSize + 1, 0x00,
            SHA224_BLOCK_SIZE - (ctx->chunkSize + 1));
        processChunk(ctx);
        memset(wbytes, 0x00, SHA224_BLOCK_SIZE - 8);
    }
    ctx->w[14] = HTOBE32((uint32_t)(ctx->length >> 32));
    ctx->w[15] = HTOBE32((uint32_t)ctx->length);
    processChunk(ctx);
    for (int i = 0; i < 7; ++i) {
        uint32_t tmp = HTOBE32(ctx->h[i]);
        memcpy(hash + 4 * i, &tmp, 4);
    }
}

void SHA224_HMAC_Init(SHA224_CTX* ctx, const void* key, size_t keyLen)
{
    uint8_t K0[SHA224_BLOCK_SIZE] = { 0 };
    if (keyLen > SHA224_BLOCK_SIZE) {
        SHA224_Init(ctx);
        SHA224_Update(ctx, key, keyLen);
        SHA224_Final(ctx, K0);
    }
    else {
        memcpy(K0, key, keyLen);
    }
    for (int i = 0; i < SHA224_BLOCK_SIZE; ++i)
        K0[i] ^= 0x36; 
    SHA224_Init(ctx);
    SHA224_Update(ctx, K0, SHA224_BLOCK_SIZE);
}

void SHA224_HMAC_Update(SHA224_CTX* ctx, const void* data, size_t len)
{
    SHA224_Update(ctx, data, len);
}

void SHA224_HMAC_Final(SHA224_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA224_DIGEST_SIZE])
{
    uint8_t innerHash[SHA224_DIGEST_SIZE];
    SHA224_Final(ctx, innerHash);

    uint8_t K0[SHA224_BLOCK_SIZE] = { 0 };
    if (keyLen > SHA224_BLOCK_SIZE) {
        SHA224_Init(ctx);
        SHA224_Update(ctx, key, keyLen);
        SHA224_Final(ctx, K0);
    }
    else {
        memcpy(K0, key, keyLen);
    }
    for (int i = 0; i < SHA224_BLOCK_SIZE; ++i)
        K0[i] ^= 0x5c;

    SHA224_Init(ctx);
    SHA224_Update(ctx, K0, SHA224_BLOCK_SIZE);
    SHA224_Update(ctx, innerHash, SHA224_DIGEST_SIZE);
    SHA224_Final(ctx, mac);
}