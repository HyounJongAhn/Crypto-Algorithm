#include "rsa_pss.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define HASH_LEN 32
#define SALT_LEN HASH_LEN
#define M_PRIME_LEN (8 + HASH_LEN + SALT_LEN)

// MGF1 (Mask Generation Function) using SHA256
static int mgf1(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len)
{
    SHA256_CTX sha_ctx;
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

// 임시 랜덤 바이트 생성 (실제 암호 RNG 권장)
static void get_random_bytes(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

// EMSA-PSS 인코딩 (PSS padding + 해시 + 마스크 생성)
static int emsa_pss_encode(const uint8_t* message,size_t messeage_len, size_t emBits, uint8_t* EM, size_t salt_len) {
    size_t emLen = (emBits + 7) / 8;
    if (emLen < HASH_LEN + salt_len + 2) return -1;

    SHA256_CTX sha_ctx;
    uint8_t mHash[HASH_LEN];
    uint8_t hashvalue[HASH_LEN];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, message, messeage_len);
    SHA256_Final(&sha_ctx, mHash);

    uint8_t* salt = (uint8_t*)malloc(salt_len);
    if (!salt) return -2;
    get_random_bytes(salt, salt_len);

    size_t m_prime_len = 8 + HASH_LEN + salt_len;
    uint8_t* M_prime = (uint8_t*)malloc(m_prime_len);
    if (!M_prime) {
        free(salt);
        return -2;
    }
    memset(M_prime, 0x00, 8);
    memcpy(M_prime + 8, mHash, HASH_LEN);
    memcpy(M_prime + 8 + HASH_LEN, salt, salt_len);

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, M_prime, m_prime_len);
    SHA256_Final(&sha_ctx, hashvalue);

	uint8_t* DB = (uint8_t*)malloc(emLen - HASH_LEN - 1);

	size_t db_len = emLen - HASH_LEN - 1;
    size_t ps_len = db_len - salt_len - 1;
    memset(DB, 0x00, ps_len);
    DB[ps_len] = 0x01;
    memcpy(DB + ps_len + 1, salt, salt_len);

    uint8_t* dbMask = (uint8_t*)malloc(emLen - HASH_LEN - 1);
    if (!dbMask) {
        free(salt);
        free(M_prime);
        return -2;
    }

    mgf1(hashvalue, HASH_LEN, dbMask, db_len);

    for (size_t i = 0; i < emLen - HASH_LEN - 1; i++) {
        DB[i] ^= dbMask[i];
    }

    size_t bits_to_clear = (8 * emLen) - emBits;
	DB[0] &= (0xFF >> bits_to_clear);

	memcpy(EM, DB, db_len);
    memcpy(EM + db_len, hashvalue, HASH_LEN);
    EM[emLen - 1] = 0xBC;
    free(dbMask);
    free(salt);
    free(M_prime);

    return 0;
}

// EMSA-PSS 디코딩 및 검증
static int emsa_pss_decode(const uint8_t* EM, size_t em_len, size_t emBits, const uint8_t* message, size_t msg_len, size_t salt_len) {
    if (EM[em_len - 1] != 0xBC) return -1;

    uint8_t mhash[HASH_LEN];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, msg_len);
    SHA256_Final(&ctx, mhash);

    size_t db_len = em_len - HASH_LEN - 1;
    const uint8_t* H = EM + db_len;

    size_t bits_to_clear = (8 * em_len) - emBits;
    size_t full_bytes = bits_to_clear / 8;
    size_t partial_bits = bits_to_clear % 8;

    for (size_t i = 0; i < full_bytes; i++) {
        if (EM[i] != 0x00) return -5;
    }
    if (partial_bits > 0) {
        uint8_t mask = 0xFF << (8 - partial_bits);
        if ((EM[full_bytes] & mask) != 0) return -5;
    }

    uint8_t* dbMask = (uint8_t*)malloc(db_len);
    uint8_t* DB = (uint8_t*)malloc(db_len);
    if (!dbMask || !DB) {
        free(dbMask); free(DB);
        return -2;
    }

    mgf1(H, HASH_LEN, dbMask, db_len);

    for (size_t i = 0; i < db_len; i++) {
        DB[i] = EM[i] ^ dbMask[i];
    }
    free(dbMask);

    DB[0] &= (0xFF >> bits_to_clear);

    size_t ps_len = db_len - salt_len - 1;
    if (ps_len +1 + salt_len > db_len || DB[ps_len] != 0x01) {
        free(DB);
        return -6;
    }

    uint8_t* salt = (uint8_t*)(DB + ps_len + 1);

    uint8_t M_prime[8 + HASH_LEN + SALT_LEN];
    memset(M_prime, 0x00, 8);
    memcpy(M_prime + 8, mhash, HASH_LEN);
    memcpy(M_prime + 8 + HASH_LEN, salt, salt_len);

    uint8_t H_prime[HASH_LEN];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, M_prime, sizeof(M_prime));
    SHA256_Final(&ctx, H_prime);
    int result = memcmp(H, H_prime, HASH_LEN);
    //free(M_prime);
    free(DB);
    //free(H_prime);

    return (result == 0) ? 0 : -7;
}

// RSA-PSS 서명 생성
int rsa_pss_sign(rsa_context* ctx,
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len)
{
    if (*signature_len < ctx->len) {
        return -1;
    }

    size_t emBits = ctx->len * 8 - 1;
    uint8_t* EM = (uint8_t*)calloc(ctx->len, 1);
    if (!EM) return -2;

    int ret = emsa_pss_encode(message, message_len, emBits, EM, SALT_LEN);
    if (ret != 0) {
        free(EM);
        return -3;
    }

    ret = rsa_private(ctx, EM, signature);
    free(EM);
    if (ret != 0) return ret;

    *signature_len = ctx->len;
    return 0;
}

// RSA-PSS 서명 검증
int rsa_pss_verify(rsa_context* ctx,
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len)
{
    if (signature_len != ctx->len) {
        return -1;
    }

    uint8_t* EM = (uint8_t*)malloc(ctx->len);
    if (!EM) return -2;

    int ret = rsa_public(ctx, (uint8_t*)signature, EM);
    if (ret != 0) {
        free(EM);
        return ret;
    }

    ret = emsa_pss_decode(EM, ctx->len, ctx->len * 8 - 1, message, message_len, SALT_LEN);

    free(EM);
    return ret;
}
