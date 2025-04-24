#include "LSH512.h"
#include <string.h>

static void compress512(LSH512_CTX* st, const Byte* db)
{
    u64 m[16 * (NS512 + 1)], T[16];
    int j, l, k;
    u64 vl, vr;

    for (l = 0; l < 32; ++l) {
        m[l] = U8TO64_LE(db + 8 * l);
    }
    for (j = 2; j <= NS512; ++j) {
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

    for (j = 0; j < NS512 / 2; ++j) {
        k = 2 * j;
        for (l = 0; l < 8; ++l) {
            vl = st->cv512[l] ^ m[16 * k + l];
            vr = st->cv512[l + 8] ^ m[16 * k + l + 8];
            vl = ROL64(vl + vr, 23) ^ SC512[k][l];
            vr = ROL64(vr + vl, 59);
            T[l] = vr + vl;
            T[l + 8] = ROL64(vr, gamma512[l]);
        }
        st->cv512[0] = T[6]; st->cv512[8] = T[2];
        st->cv512[1] = T[4]; st->cv512[9] = T[0];
        st->cv512[2] = T[5]; st->cv512[10] = T[1];
        st->cv512[3] = T[7]; st->cv512[11] = T[3];
        st->cv512[4] = T[12];st->cv512[12] = T[8];
        st->cv512[5] = T[15];st->cv512[13] = T[11];
        st->cv512[6] = T[14];st->cv512[14] = T[10];
        st->cv512[7] = T[13];st->cv512[15] = T[9];

        k = 2 * j + 1;
        for (l = 0; l < 8; ++l) {
            vl = st->cv512[l] ^ m[16 * k + l];
            vr = st->cv512[l + 8] ^ m[16 * k + l + 8];
            vl = ROL64(vl + vr, 7) ^ SC512[k][l];
            vr = ROL64(vl + vr, 3);
            T[l] = vr + vl;
            T[l + 8] = ROL64(vr, gamma512[l]);
        }
        st->cv512[0] = T[6]; st->cv512[8] = T[2];
        st->cv512[1] = T[4]; st->cv512[9] = T[0];
        st->cv512[2] = T[5]; st->cv512[10] = T[1];
        st->cv512[3] = T[7]; st->cv512[11] = T[3];
        st->cv512[4] = T[12];st->cv512[12] = T[8];
        st->cv512[5] = T[15];st->cv512[13] = T[11];
        st->cv512[6] = T[14];st->cv512[14] = T[10];
        st->cv512[7] = T[13];st->cv512[15] = T[9];
    }

    for (l = 0; l < 16; ++l) {
        st->cv512[l] ^= m[16 * NS512 + l];
    }
}

static int __init512(LSH512_CTX* st, int bits)
{
    if (bits != 512) return FAIL;
    memcpy(st->cv512, IV512, sizeof IV512);
    st->hashbitlen = bits;
    return SUCCESS;
}

static void __update512(LSH512_CTX* st, const void* data, DataLength databitlen)
{
    const Byte* b = (const Byte*)data;
    u64 numBlocks = (databitlen >> 11) + 1;
    u64 temp;
    u32 pos1, pos2;
    u64 i;

    for (i = 0; i < numBlocks - 1; ++i) {
        compress512(st, b);
        b += LSH512_BLOCK_SIZE;
    }

    if ((u32)(databitlen & 0x7FF)) {
        temp = (numBlocks - 1) << 8; 
        pos1 = (u32)((databitlen >> 3) - temp);
        pos2 = (u32)(databitlen & 0x7);

        if (pos2) {
            memcpy(st->Last512, b, pos1);
            st->Last512[pos1] = (b[pos1] & (0xFF << (8 - pos2))) ^ (1 << (7 - pos2));
            if (pos1 != LSH512_BLOCK_SIZE - 1)
                memset(st->Last512 + pos1 + 1, 0, (LSH512_BLOCK_SIZE - 1) - pos1);
        }
        else {
            memcpy(st->Last512, b, pos1);
            st->Last512[pos1] = 0x80;
            if (pos1 != LSH512_BLOCK_SIZE - 1)
                memset(st->Last512 + pos1 + 1, 0, (LSH512_BLOCK_SIZE - 1) - pos1);
        }
    }
    else {
        st->Last512[0] = 0x80;
        memset(st->Last512 + 1, 0, LSH512_BLOCK_SIZE - 1);
    }
}

static void __final512(LSH512_CTX* st, Byte* out)
{
    u64 H[8];
    int l;

    compress512(st, st->Last512);
    for (l = 0; l < 8; ++l) {
        H[l] = st->cv512[l] ^ st->cv512[l + 8];
    }

    for (l = 0; l < (st->hashbitlen >> 3); ++l) {
        out[l] = (Byte)(H[l >> 3] >> ((l << 3) & 0x3F));
    }
}


void LSH512_Init(LSH512_CTX* ctx)
{
    __init512(ctx, 512);
}

void LSH512_Update(LSH512_CTX* ctx, const void* data, size_t len)
{
    __update512(ctx, data, (DataLength)len * 8);
}

void LSH512_Final(LSH512_CTX* ctx, uint8_t hash[LSH512_DIGEST_SIZE])
{
    __final512(ctx, hash);
}
