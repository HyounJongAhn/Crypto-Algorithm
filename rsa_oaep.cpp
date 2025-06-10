#include "rsa_oaep.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define HASH_LEN 32
#define SEED_LEN HASH_LEN
#define OAEP_LABEL NULL
#define OAEP_LABEL_LEN 0
// MGF1 (Mask Generation Function) using SHA256
static int mgf1(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len)
{
    uint8_t counter[4];
    uint8_t digest[HASH_LEN];
    size_t generated = 0;
    uint32_t ctr = 0;

    while (generated < mask_len) {
        counter[0] = (ctr >> 24) & 0xFF;
        counter[1] = (ctr >> 16) & 0xFF;
        counter[2] = (ctr >> 8) & 0xFF;
        counter[3] = ctr & 0xFF;
        ctr++;

        SHA256_CTX sha_ctx;
        SHA256_Init(&sha_ctx);
        SHA256_Update(&sha_ctx, seed, seed_len);
        SHA256_Update(&sha_ctx, counter, 4);
        SHA256_Final(&sha_ctx, digest);

        size_t to_copy = (mask_len - generated) < HASH_LEN ? (mask_len - generated) : HASH_LEN;
        memcpy(mask + generated, digest, to_copy);
        generated += to_copy;
    }
    return 0;
}

// �ӽ� ���� ����Ʈ ���� (���� ��ȣ RNG ����)
static void get_random_bytes(uint8_t* buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

int rsa_oaep_encrypt(rsa_context* ctx,
    const uint8_t* input, size_t input_len,
    uint8_t* output, size_t* output_len)
{
    size_t k = ctx->len;  // RSA ��ⷯ�� ũ�� (����Ʈ)
    size_t hLen = HASH_LEN;

    if (input_len > k - 2 * hLen - 2)
        return -1; // �޽��� �ʹ� ŭ

    // ������ �� �޸� �Ҵ��� �� ��° �ڵ�� �����ϰ� ����
    uint8_t* DB = (uint8_t*)malloc(k - hLen - 1);
    uint8_t* seed = (uint8_t*)malloc(hLen);
    uint8_t* dbMask = (uint8_t*)malloc(k - hLen - 1);
    uint8_t* maskedDB = (uint8_t*)malloc(k - hLen - 1);
    uint8_t seedMask[HASH_LEN], maskedSeed[HASH_LEN];
    uint8_t* EM = (uint8_t*)malloc(k);

    if (!DB || !seed || !dbMask || !maskedDB || !EM) {
        free(DB); free(seed); free(dbMask); free(maskedDB); free(EM);
        return -2;
    }

    // lHash = SHA256(LABEL)
    uint8_t lHash[HASH_LEN];
    SHA256_CTX SHA_ctx;
    SHA256_Init(&SHA_ctx);
    SHA256_Update(&SHA_ctx, (const uint8_t*)OAEP_LABEL, OAEP_LABEL_LEN);
    SHA256_Final(&SHA_ctx, lHash);

    // PS ���� ���
    size_t ps_len = k - 2 * hLen - 2 - input_len;

    // DB = lHash || PS || 0x01 || �޽���
    memcpy(DB, lHash, hLen);
    memset(DB + hLen, 0x00, ps_len);
    DB[hLen + ps_len] = 0x01;
    memcpy(DB + hLen + ps_len + 1, input, input_len);

    // seed ���� ����
    get_random_bytes(seed, hLen);

    // dbMask = MGF1(seed, k - hLen - 1)
    mgf1(seed, hLen, dbMask, k - hLen - 1);

    // maskedDB = DB XOR dbMask
    for (size_t i = 0; i < k - hLen - 1; i++)
        maskedDB[i] = DB[i] ^ dbMask[i];

    // seedMask = MGF1(maskedDB, hLen)
    mgf1(maskedDB, k - hLen - 1, seedMask, hLen);

    // maskedSeed = seed XOR seedMask
    for (size_t i = 0; i < hLen; i++)
        maskedSeed[i] = seed[i] ^ seedMask[i];

    // EM = 0x00 || maskedSeed || maskedDB
    EM[0] = 0x00;
    memcpy(EM + 1, maskedSeed, hLen);
    memcpy(EM + 1 + hLen, maskedDB, k - hLen - 1);

    // RSA ����Ű ���� (EM^e mod n)
    int ret = rsa_public(ctx, EM, output);

    free(DB);
    free(seed);
    free(dbMask);
    free(maskedDB);
    free(EM);

    if (ret != 0)
        return ret;

    *output_len = k;
    return 0;
}


int rsa_oaep_decrypt(rsa_context* ctx,
    const uint8_t* input, size_t input_len,
    uint8_t* output, size_t* output_len)
{
    if (input_len != ctx->len)
        return -1;

    uint8_t* EM = (uint8_t*)malloc(ctx->len);
    if (!EM)
        return -2;

    int ret = rsa_private(ctx, (uint8_t*)input, EM);
    if (ret != 0) {
        free(EM);
        return ret;
    }

    // EM ù ����Ʈ �ݵ�� 0x00���� ��
    if (EM[0] != 0x00) {
        free(EM);
        return -3;
    }

    size_t k = ctx->len;
    size_t hLen = HASH_LEN;

    // lHash ��� (�� ���ڿ�)
    uint8_t lHash[HASH_LEN];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    uint8_t empty_label[1] = { 0 };
    SHA256_Update(&sha_ctx, empty_label, 0);
    SHA256_Final(&sha_ctx, lHash);

    // maskedSeed, maskedDB �и�
    uint8_t maskedSeed[HASH_LEN];
    uint8_t* maskedDB = EM + 1 + hLen;
    size_t dbLen = k - hLen - 1;

    memcpy(maskedSeed, EM + 1, hLen);

    // seed = maskedSeed XOR MGF1(maskedDB, hLen)
    uint8_t seed[HASH_LEN];
    mgf1(maskedDB, dbLen, seed, hLen);
    for (size_t i = 0; i < hLen; i++) {
        seed[i] ^= maskedSeed[i];
    }

    // dbMask = MGF1(seed, dbLen)
    uint8_t* dbMask = (uint8_t*)malloc(dbLen);
    uint8_t* DB = (uint8_t*)malloc(dbLen);
    if (!dbMask || !DB) {
        free(EM);
        free(dbMask);
        free(DB);
        return -4;
    }
    mgf1(seed, hLen, dbMask, dbLen);

    // DB = maskedDB XOR dbMask
    for (size_t i = 0; i < dbLen; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    // lHash ���� : DB ó�� hLen ����Ʈ�� lHash�� ��ġ�ؾ� ��
    if (memcmp(DB, lHash, hLen) != 0) {
        free(EM);
        free(dbMask);
        free(DB);
        return -5;
    }

    // PS(0x00 ����) + 0x01 + M �е� ���� Ȯ��
    size_t index = hLen;
    while (index < dbLen) {
        if (DB[index] == 0x01) {
            index++;
            break;
        }
        else if (DB[index] != 0x00) {
            free(EM);
            free(dbMask);
            free(DB);
            return -6;
        }
        index++;
    }

    if (index > dbLen) {
        free(EM);
        free(dbMask);
        free(DB);
        return -7;
    }

    // �޽��� ���� ��� �� ��� ���ۿ� ����
    size_t mLen = dbLen - index;
    if (mLen > *output_len) {
        free(EM);
        free(dbMask);
        free(DB);
        return -8;
    }
    memcpy(output, DB + index, mLen);
    *output_len = mLen;

    free(EM);
    free(dbMask);
    free(DB);

    return 0;
}
