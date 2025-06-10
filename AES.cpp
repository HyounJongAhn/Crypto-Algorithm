// AES.c
#include "AES.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void AES_AddRoundKey(unsigned char state[4][Nb], const unsigned char* rk) {
    for (unsigned i = 0; i < 4; ++i)
        for (unsigned j = 0; j < Nb; ++j)
            state[i][j] ^= rk[i + 4 * j];
}

static void AES_SubBytes(unsigned char state[4][Nb]) {
    for (unsigned i = 0; i < 4; ++i)
        for (unsigned j = 0; j < Nb; ++j) {
            unsigned char v = state[i][j];
            state[i][j] = sbox[v >> 4][v & 0x0F];
        }
}

static void AES_InvSubBytes(unsigned char state[4][Nb]) {
    for (unsigned i = 0; i < 4; ++i)
        for (unsigned j = 0; j < Nb; ++j) {
            unsigned char v = state[i][j];
            state[i][j] = inv_sbox[v >> 4][v & 0x0F];
        }
}

static void AES_ShiftRows(unsigned char state[4][Nb]) {
    unsigned char tmp[Nb];
    for (unsigned j = 0;j < Nb;++j) tmp[j] = state[1][(j + 1) % Nb];
    memcpy(state[1], tmp, Nb);
    for (unsigned j = 0;j < Nb;++j) tmp[j] = state[2][(j + 2) % Nb];
    memcpy(state[2], tmp, Nb);
    for (unsigned j = 0;j < Nb;++j) tmp[j] = state[3][(j + 3) % Nb];
    memcpy(state[3], tmp, Nb);
}

static void AES_InvShiftRows(unsigned char state[4][Nb]) {
    unsigned char tmp[Nb];
    for (unsigned j = 0;j < Nb;++j) tmp[j] = state[1][(j + Nb - 1) % Nb];
    memcpy(state[1], tmp, Nb);
    for (unsigned j = 0;j < Nb;++j) tmp[j] = state[2][(j + Nb - 2) % Nb];
    memcpy(state[2], tmp, Nb);
    for (unsigned j = 0;j < Nb;++j) tmp[j] = state[3][(j + Nb - 3) % Nb];
    memcpy(state[3], tmp, Nb);
}

static unsigned char xtime(unsigned char x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static void AES_MixColumns(unsigned char state[4][Nb]) {
    unsigned char t[4][Nb] = { 0 };
    for (unsigned i = 0;i < 4;++i) {
        for (unsigned k = 0;k < 4;++k) {
            unsigned char coef = CMDS[i][k];
            for (unsigned j = 0;j < Nb;++j) {
                unsigned char v = state[k][j];
                if (coef == 1) t[i][j] ^= v;
                else            t[i][j] ^= GF_MUL_TABLE[coef][v];
            }
        }
    }
    memcpy(state, t, sizeof t);
}

static void AES_InvMixColumns(unsigned char state[4][Nb]) {
    unsigned char t[4][Nb] = { 0 };
    for (unsigned i = 0;i < 4;++i) {
        for (unsigned k = 0;k < 4;++k) {
            unsigned char coef = INV_CMDS[i][k];
            for (unsigned j = 0;j < Nb;++j) {
                unsigned char v = state[k][j];
                t[i][j] ^= GF_MUL_TABLE[coef][v];
            }
        }
    }
    memcpy(state, t, sizeof t);
}

void AES_Rcon(unsigned char* a, unsigned int n) {
    unsigned char c = 1;
    for (unsigned i = 1;i < n;++i) c = xtime(c);
    a[0] = c; a[1] = a[2] = a[3] = 0;
}

void AES_RotWord(unsigned char* a) {
    unsigned char t = a[0];
    a[0] = a[1]; a[1] = a[2]; a[2] = a[3]; a[3] = t;
}

void AES_SubWord(unsigned char* a) {
    for (int i = 0;i < 4;++i) {
        unsigned char v = a[i];
        a[i] = sbox[v >> 4][v & 0x0F];
    }
}

void AES_XorWords(unsigned char* a, unsigned char* b, unsigned char* c) {
    for (int i = 0;i < 4;++i) c[i] = a[i] ^ b[i];
}

void AES_init(AES* ctx, const uint8_t* mk, uint8_t mk_len)
{
    /* key 길이→Nk, Nr 결정 */
    switch (mk_len) {
    case 16: ctx->Nk = 4;  ctx->Nr = 10; break;
    case 24: ctx->Nk = 6;  ctx->Nr = 12; break;
    case 32: ctx->Nk = 8;  ctx->Nr = 14; break;
    default:
        fprintf(stderr, "AES_init: unsupported keylen %u\n", mk_len);
        exit(1);
    }
    ctx->roundKeys = (unsigned char*)malloc(4 * Nb * (ctx->Nr + 1));
    memcpy(ctx->key, mk, mk_len);
    AES_KeySetup(ctx->key, ctx->roundKeys, ctx->Nk, ctx->Nr);   /* 한 번만! */
}

void AES_KeySetup(const unsigned char key[], unsigned char w[], unsigned int Nk, unsigned int Nr) {
    unsigned int i = 0;
    for (; i < 4 * Nk; ++i) w[i] = key[i];
    for (; i < 4 * Nb * (Nr + 1); i += 4) {
        unsigned char tmp[4];
        memcpy(tmp, &w[i - 4], 4);
        if ((i / 4) % Nk == 0) {
            AES_RotWord(tmp);
            AES_SubWord(tmp);
            unsigned char rc[4];
            AES_Rcon(rc, i / (Nk * 4));
            AES_XorWords(tmp, rc, tmp);
        }
        else if (Nk > 6 && (i / 4) % Nk == 4) {
            AES_SubWord(tmp);
        }
        w[i + 0] = w[i - 4 * Nk + 0] ^ tmp[0];
        w[i + 1] = w[i - 4 * Nk + 1] ^ tmp[1];
        w[i + 2] = w[i - 4 * Nk + 2] ^ tmp[2];
        w[i + 3] = w[i - 4 * Nk + 3] ^ tmp[3];
    }
}

void AES_REAL_EncryptBlock(const unsigned char* in, unsigned char* out, AES* aes) {
    unsigned char state[4][Nb];
    for (unsigned i = 0;i < 4;++i)for (unsigned j = 0;j < Nb;++j) state[i][j] = in[i + 4 * j];
    AES_AddRoundKey(state, aes->roundKeys);
    for (unsigned r = 1;r < aes->Nr;++r) {
        AES_SubBytes(state);
        AES_ShiftRows(state);
        AES_MixColumns(state);
        AES_AddRoundKey(state, aes->roundKeys + r * 4 * Nb);
    }
    AES_SubBytes(state);
    AES_ShiftRows(state);
    AES_AddRoundKey(state, aes->roundKeys + aes->Nr * 4 * Nb);
    for (unsigned i = 0;i < 4;++i)for (unsigned j = 0;j < Nb;++j) out[i + 4 * j] = state[i][j];
}

void AES_REAL_DecryptBlock(const unsigned char* in, unsigned char* out, AES* aes) {
    unsigned char state[4][Nb];
    for (unsigned i = 0;i < 4;++i)for (unsigned j = 0;j < Nb;++j) state[i][j] = in[i + 4 * j];
    AES_AddRoundKey(state, aes->roundKeys + aes->Nr * 4 * Nb);
    for (int r = aes->Nr - 1;r > 0;--r) {
        AES_InvSubBytes(state);
        AES_InvShiftRows(state);
        AES_AddRoundKey(state, aes->roundKeys + r * 4 * Nb);
        AES_InvMixColumns(state);
    }
    AES_InvSubBytes(state);
    AES_InvShiftRows(state);
    AES_AddRoundKey(state, aes->roundKeys);
    for (unsigned i = 0;i < 4;++i)for (unsigned j = 0;j < Nb;++j) out[i + 4 * j] = state[i][j];
}

void AES_encrypt(AES* aes, unsigned char* ct, const unsigned char* pt, size_t blocks) {
    for (size_t b = 0; b < blocks; ++b) {
        AES_REAL_EncryptBlock(pt + 16 * b, ct + 16 * b, aes);
    }
}

void AES_decrypt(AES* aes, unsigned char* pt, const unsigned char* ct, size_t blocks) {
    for (size_t b = 0; b < blocks; ++b) {
        AES_REAL_DecryptBlock(ct + 16 * b, pt + 16 * b, aes);
    }
}


void AES_CheckLength(unsigned int len) {
    if (len % blockBytesLen != 0) {
        fprintf(stderr, "AES_CheckLength: length must be multiple of %d\n", blockBytesLen);
        exit(1);
    }
}

void AES_free(AES* aes) {
    free(aes->roundKeys);
}
