#include "sha512.h"
#include <string.h>

#define BE64TOH(x) ( \
    (((x) & 0xFF00000000000000ULL) >> 56) | \
    (((x) & 0x00FF000000000000ULL) >> 40) | \
    (((x) & 0x0000FF0000000000ULL) >> 24) | \
    (((x) & 0x000000FF00000000ULL) >>  8) | \
    (((x) & 0x00000000FF000000ULL) <<  8) | \
    (((x) & 0x0000000000FF0000ULL) << 24) | \
    (((x) & 0x000000000000FF00ULL) << 40) | \
    (((x) & 0x00000000000000FFULL) << 56))
#define HTOBE64(x) BE64TOH(x)

#define ROTR64(x,n)  (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR64(x,n)   ((x) >> (n))
#define CH64(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0_64(x)  (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define BSIG1_64(x)  (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define SSIG0_64(x)  (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR64(x, 7))
#define SSIG1_64(x)  (ROTR64(x,19) ^ ROTR64(x,61) ^ SHR64(x, 6))

static const uint64_t K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
    0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
    0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
    0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
    0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
    0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
    0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
    0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
    0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
    0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
    0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
    0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
    0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
    0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
    0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
    0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
    0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
    0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
    0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
    0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
    0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

static void processChunk(SHA512_CTX* ctx)
{
    uint64_t a, b, c, d, e, f, g, h, T1, T2;
    for (int i = 0; i < 16; ++i) {
        ctx->w[i] = BE64TOH(ctx->w[i]);
    }
    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t W = (i < 16
            ? ctx->w[i]
            : (ctx->w[i & 0x0F] = SSIG1_64(ctx->w[(i - 2) & 0x0F])
                + ctx->w[(i - 7) & 0x0F]
                + SSIG0_64(ctx->w[(i - 15) & 0x0F])
                + ctx->w[(i - 16) & 0x0F]));
        T1 = h + BSIG1_64(e) + CH64(e, f, g) + K[i] + W;
        T2 = BSIG0_64(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

void SHA512_Init(SHA512_CTX* ctx)
{
    ctx->h[0] = 0x6A09E667F3BCC908ULL;
    ctx->h[1] = 0xBB67AE8584CAA73BULL;
    ctx->h[2] = 0x3C6EF372FE94F82BULL;
    ctx->h[3] = 0xA54FF53A5F1D36F1ULL;
    ctx->h[4] = 0x510E527FADE682D1ULL;
    ctx->h[5] = 0x9B05688C2B3E6C1FULL;
    ctx->h[6] = 0x1F83D9ABFB41BD6BULL;
    ctx->h[7] = 0x5BE0CD19137E2179ULL;
    ctx->lengthLow = 0;
    ctx->lengthHigh = 0;
    ctx->chunkSize = 0;
}

void SHA512_Update(SHA512_CTX* ctx, const void* data, size_t len)
{
    ctx->lengthLow += ((uint64_t)len << 3);
    ctx->lengthHigh += ((uint64_t)len >> 61);
    if (ctx->lengthLow < ((uint64_t)len << 3)) ctx->lengthHigh++;

    const uint8_t* p = (const uint8_t*)data;
    while (len) {
        size_t take = SHA512_BLOCK_SIZE - ctx->chunkSize;
        if (take > len) take = len;
        memcpy(((uint8_t*)ctx->w) + ctx->chunkSize, p, take);
        ctx->chunkSize += take;
        p += take;
        len -= take;
        if (ctx->chunkSize == SHA512_BLOCK_SIZE) {
            processChunk(ctx);
            ctx->chunkSize = 0;
        }
    }
}

void SHA512_Final(SHA512_CTX* ctx, uint8_t hash[SHA512_DIGEST_SIZE])
{
    uint8_t* buf = (uint8_t*)ctx->w;

    if (ctx->chunkSize <= SHA512_BLOCK_SIZE - 17) {
        buf[ctx->chunkSize++] = 0x80;
        memset(buf + ctx->chunkSize, 0, SHA512_BLOCK_SIZE - 16 - ctx->chunkSize);
    }
    else {
        buf[ctx->chunkSize++] = 0x80;
        memset(buf + ctx->chunkSize, 0, SHA512_BLOCK_SIZE - ctx->chunkSize);
        processChunk(ctx);
        memset(buf, 0, SHA512_BLOCK_SIZE - 16);
    }
    ((uint64_t*)buf)[14] = HTOBE64(ctx->lengthHigh);
    ((uint64_t*)buf)[15] = HTOBE64(ctx->lengthLow);
    processChunk(ctx);

    for (int i = 0; i < 8; ++i) {
        uint64_t hv = HTOBE64(ctx->h[i]);
        memcpy(hash + 8 * i, &hv, 8);
    }
}

void SHA512_HMAC_Init(SHA512_CTX* ctx, const void* key, size_t keyLen)
{
    uint8_t K0[SHA512_BLOCK_SIZE] = { 0 };
    if (keyLen > SHA512_BLOCK_SIZE) {
        SHA512_Init(ctx);
        SHA512_Update(ctx, key, keyLen);
        SHA512_Final(ctx, K0);
    }
    else {
        memcpy(K0, key, keyLen);
    }
    for (size_t i = 0; i < SHA512_BLOCK_SIZE; ++i)
        K0[i] ^= 0x36;
    SHA512_Init(ctx);
    SHA512_Update(ctx, K0, SHA512_BLOCK_SIZE);
}

void SHA512_HMAC_Update(SHA512_CTX* ctx, const void* data, size_t len)
{
    SHA512_Update(ctx, data, len);
}

void SHA512_HMAC_Final(SHA512_CTX* ctx, const void* key, size_t keyLen, uint8_t mac[SHA512_DIGEST_SIZE])
{
    uint8_t inner[SHA512_DIGEST_SIZE];
    SHA512_Final(ctx, inner);

    uint8_t K0[SHA512_BLOCK_SIZE] = { 0 };
    if (keyLen > SHA512_BLOCK_SIZE) {
        SHA512_Init(ctx);
        SHA512_Update(ctx, key, keyLen);
        SHA512_Final(ctx, K0);
    }
    else {
        memcpy(K0, key, keyLen);
    }
    for (size_t i = 0; i < SHA512_BLOCK_SIZE; ++i)
        K0[i] ^= 0x5C;

    SHA512_Init(ctx);
    SHA512_Update(ctx, K0, SHA512_BLOCK_SIZE);
    SHA512_Update(ctx, inner, SHA512_DIGEST_SIZE);
    SHA512_Final(ctx, mac);
}
