#include "LSH256.h"
#include <string.h>

static void compress256(LSH256_CTX* st, const Byte* db)
{
    u32 m[16 * (NS256 + 1)], T[16];
    int j, l, k;
    u32 vl, vr;

    for (l = 0; l < 32; ++l) {
        m[l] = U8TO32_LE(db + 4 * l);
    }
    for (j = 2; j <= NS256; ++j) {
        k = 16 * j;
        m[k + 0] = m[k - 16] + m[k - 29];
        m[k + 1] = m[k - 15] + m[k - 30];
        m[k + 2] = m[k - 14] + m[k - 32];
        m[k + 3] = m[k - 13] + m[k - 31];
        m[k + 4] = m[k - 12] + m[k - 25];
        m[k + 5] = m[k - 11] + m[k - 28];
        m[k + 6] = m[k - 10] + m[k - 27];
        m[k + 7] = m[k - 9] + m[k - 26];
        m[k + 8] = m[k - 8] + m[k - 21];
        m[k + 9] = m[k - 7] + m[k - 22];
        m[k + 10] = m[k - 6] + m[k - 24];
        m[k + 11] = m[k - 5] + m[k - 23];
        m[k + 12] = m[k - 4] + m[k - 17];
        m[k + 13] = m[k - 3] + m[k - 20];
        m[k + 14] = m[k - 2] + m[k - 19];
        m[k + 15] = m[k - 1] + m[k - 18];
    }

    for (j = 0; j < NS256 / 2; ++j) {
        k = 2 * j;
        for (l = 0; l < 8; ++l) {
            vl = st->cv256[l] ^ m[16 * k + l];
            vr = st->cv256[l + 8] ^ m[16 * k + l + 8];
            vl = ROL32(vl + vr, 29) ^ SC256[k][l];
            vr = ROL32(vr + vl, 1);
            T[l] = vr + vl;
            T[l + 8] = ROL32(vr, gamma256[l]);
        }
        st->cv256[0] = T[6]; st->cv256[8] = T[2];
        st->cv256[1] = T[4]; st->cv256[9] = T[0];
        st->cv256[2] = T[5]; st->cv256[10] = T[1];
        st->cv256[3] = T[7]; st->cv256[11] = T[3];
        st->cv256[4] = T[12];st->cv256[12] = T[8];
        st->cv256[5] = T[15];st->cv256[13] = T[11];
        st->cv256[6] = T[14];st->cv256[14] = T[10];
        st->cv256[7] = T[13];st->cv256[15] = T[9];

        k = 2 * j + 1;
        for (l = 0; l < 8; ++l) {
            vl = st->cv256[l] ^ m[16 * k + l];
            vr = st->cv256[l + 8] ^ m[16 * k + l + 8];
            vl = ROL32(vl + vr, 5) ^ SC256[k][l];
            vr = ROL32(vl + vr, 17);
            T[l] = vr + vl;
            T[l + 8] = ROL32(vr, gamma256[l]);
        }
        st->cv256[0] = T[6]; st->cv256[8] = T[2];
        st->cv256[1] = T[4]; st->cv256[9] = T[0];
        st->cv256[2] = T[5]; st->cv256[10] = T[1];
        st->cv256[3] = T[7]; st->cv256[11] = T[3];
        st->cv256[4] = T[12];st->cv256[12] = T[8];
        st->cv256[5] = T[15];st->cv256[13] = T[11];
        st->cv256[6] = T[14];st->cv256[14] = T[10];
        st->cv256[7] = T[13];st->cv256[15] = T[9];
    }

    for (l = 0; l < 16; ++l)
        st->cv256[l] ^= m[16 * NS256 + l];
}

static int __init256(LSH256_CTX* st, int bits)
{
    if (bits != 256) return FAIL;
    memcpy(st->cv256, IV256, sizeof IV256);
    st->hashbitlen = bits;
    return SUCCESS;
}

static void __update256(LSH256_CTX* st, const void* data, DataLength databitlen)
{
    const Byte* d = (const Byte*)data;
    u64 numBlocks = (databitlen >> 10) + 1;
    u64 temp;
    u32 pos1, pos2;
    u64 i;

    for (i = 0; i < numBlocks - 1; ++i) {
        compress256(st, d);
        d += LSH256_BLOCK_SIZE;
    }

    if ((u32)(databitlen & 0x3ff)) {
        temp = (numBlocks - 1) << 7;
        pos1 = (u32)((databitlen >> 3) - temp);
        pos2 = (u32)(databitlen & 0x7);
        if (pos2) {
            memcpy(st->Last256, d, pos1);
            st->Last256[pos1] = (d[pos1] & (0xff << (8 - pos2))) ^ (1 << (7 - pos2));
            if (pos1 != 127) memset(st->Last256 + pos1 + 1, 0, 127 - pos1);
        }
        else {
            memcpy(st->Last256, d, pos1);
            st->Last256[pos1] = 0x80;
            if (pos1 != 127) memset(st->Last256 + pos1 + 1, 0, 127 - pos1);
        }
    }
    else {
        st->Last256[0] = 0x80;
        memset(st->Last256 + 1, 0, 127);
    }
}

static void __final256(LSH256_CTX* st, Byte* out)
{
    u32 H[8];
    int l;

    compress256(st, st->Last256);

    for (l = 0; l < 8; ++l)
        H[l] = st->cv256[l] ^ st->cv256[l + 8];

    for (l = 0; l < (st->hashbitlen >> 3); ++l)
        out[l] = (Byte)(H[l >> 2] >> ((l << 3) & 0x1F));
}
void LSH256_Init(LSH256_CTX* ctx)
{
    __init256(ctx, 256);
}

void LSH256_Update(LSH256_CTX* ctx, const void* data, size_t len)
{
    __update256(ctx, data, (DataLength)len * 8);
}

void LSH256_Final(LSH256_CTX* ctx, uint8_t hash[LSH256_DIGEST_SIZE])
{
    __final256(ctx, hash);
}
