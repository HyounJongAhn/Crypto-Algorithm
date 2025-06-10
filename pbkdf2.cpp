// pbkdf2_mac.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pbkdf2.h"
#include "Mac.h"
#include "Hash.h"
#include <format>
#include <cctype>
#include <iostream>
/**
 * \brief PBKDF2‐HMAC‐SHA256 구현
 *
 * \param password      비밀번호(바이트 배열)
 * \param passwordLen   비밀번호 길이(바이트)
 * \param salt          솔트(바이트 배열)
 * \param saltLen       솔트 길이(바이트)
 * \param iter          반복 횟수 (iteration count)
 * \param outKey        출력 키를 저장할 버퍼
 * \param outKeyLen     생성할 키의 길이(바이트)
 * \return 성공 시 1, 실패 시 0
 */

static bool is_hex_string(const char* s) {
    size_t L = strlen(s);
    if (L == 0 || (L % 2) != 0) return false;
    for (size_t i = 0; i < L; ++i) {
        if (!isxdigit((unsigned char)s[i])) return false;
    }
    return true;
}
static uint8_t hex2byte(char hi, char lo) {
    auto dec = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
        };
    return (dec(hi) << 4) | dec(lo);
}



int compute_PBKDF2(
	HMacAlgorithm alg,
	size_t DIGEST_LEN,
    const uint8_t* password,
    size_t passwordLen,
    const uint8_t* salt,
    size_t saltLen,
    int iter,
    uint8_t* outKey,
    int outKeyLen) 
{   
    size_t hLen = DIGEST_LEN;  
    uint8_t* U = (uint8_t*)malloc(DIGEST_LEN);  
    uint8_t* T = (uint8_t*)malloc(DIGEST_LEN);  

    if (!U || !T) {  
       if (U) free(U);  
       if (T) free(T);  
       return 0;  
    }  

    // Ensure to free allocated memory at the end of the function  
    // Example:  
    // free(U);  
    // free(T);
    // HMAC‐SHA256 출력 길이 = 32바이트
    int l, r;
    int i, j, k;
    uint8_t* salt_and_int = NULL;

    size_t outOffset = 0;
    size_t macLen;

    // l = ceil(outKeyLen / hLen)
    l = outKeyLen / hLen + ((outKeyLen % hLen) ? 1 : 0);
    // r = outKeyLen - (l-1)*hLen
    r = outKeyLen - (l - 1) * hLen;

    if (r <= 0) return 0;

    // salt || INT(i) 으로 사용할 배열 할당 (saltLen + 4 바이트)
    salt_and_int = (uint8_t*)malloc(saltLen + 4);
    if (!salt_and_int) return 0;
    memcpy(salt_and_int, salt, saltLen);

    for (i = 1; i <= l; i++) {
        // INT(i)를 Big‐Endian으로 salt_and_int 끝에 붙이기
        salt_and_int[saltLen + 0] = (uint8_t)((i >> 24) & 0xFF);
        salt_and_int[saltLen + 1] = (uint8_t)((i >> 16) & 0xFF);
        salt_and_int[saltLen + 2] = (uint8_t)((i >> 8) & 0xFF);
        salt_and_int[saltLen + 3] = (uint8_t)((i) & 0xFF);

        // U_1 = HMAC(password, salt || INT(i))
        if (compute_HMac(
            alg,
            (const char*)salt_and_int,
            saltLen + 4,
            (const char*)password,
            passwordLen,
            U,
            &macLen
        ) != 0) {
            goto cleanup;
        }
        // T = U_1 (초기값)
        memcpy(T, U, hLen);

        // U_j 반복 (j = 2..iter)
        for (j = 2; j <= iter; j++) {
            // U_j = HMAC(password, U_{j-1})
            if (compute_HMac(
                alg,
                (const char*)U,
                hLen,
                (const char*)password,
                passwordLen,
                U,
                &macLen
            ) != 0) {
                goto cleanup;
            }
            // T = T xor U_j
            for (k = 0; k < hLen; k++) {
                T[k] ^= U[k];
            }
        }

        // 결과 T를 outKey에 복사
        if (i < l) {
            memcpy(outKey + outOffset, T, hLen);
            outOffset += hLen;
        }
        else {
            // 마지막 블록(r 바이트)
            memcpy(outKey + outOffset, T, r);
            outOffset += r;
        }
    }


cleanup:
    if (salt_and_int) free(salt_and_int);
	free(U);
	free(T);
    return 1;
}

int DoPBKDF(int num) {
    // 예시: password = "password", salt = "salt", 반복 4096, 키 길이 32바이트
    HMacAlgorithm alg;
    const char* hash_name;
    uint8_t* password;
    uint8_t* salt;
    size_t       password_len;
    size_t       salt_len;
    size_t       max_digest_bytes;
    int iteration = 0;

    uint64_t max_bits;

    switch (num) {
    case 1: alg = HMAC_ALG_SHA224; hash_name = "SHA-224";
        max_bits = (((uint64_t)1) << 64) - 1;
        max_digest_bytes = SHA224_DIGEST_SIZE;
        break;
    case 2: alg = HMAC_ALG_SHA256; hash_name = "SHA-256";
        max_bits = (((uint64_t)1) << 64) - 1;
        max_digest_bytes = SHA256_DIGEST_SIZE;
        break;
    case 3: alg = HMAC_ALG_SHA384; hash_name = "SHA-384";
        max_bits = (((uint64_t)1) << 128) - 1;
        max_digest_bytes = SHA384_DIGEST_SIZE;
        break;
    case 4: alg = HMAC_ALG_SHA512; hash_name = "SHA-512";
        max_bits = (((uint64_t)1) << 128) - 1;
        max_digest_bytes = SHA512_DIGEST_SIZE;
        break;
    default:
        fprintf(stderr, "Unknown algorithm\n");
        return HMAC_ALG_UNKNOWN;
    }
    // 패스워드 입력  
    char input[8192];
    while (getchar() != '\n');
    printf("Enter password (or hex): ");
    fgets(input, sizeof input, stdin);

    input[strcspn(input, "\n")] = 0;

    if (is_hex_string(input)) {
        password_len = strlen(input) / 2;
        password = (uint8_t*)malloc(password_len);
        for (size_t i = 0; i < password_len; ++i)
            password[i] = hex2byte(input[2 * i], input[2 * i + 1]);
    }
    else {
        password_len = strlen(input);
        password = (uint8_t*)malloc(password_len);
        memcpy(password, input, password_len);
    }

    uint64_t bits = (uint64_t)password_len * 8;
    if (bits > max_bits) {
        fprintf(stderr,
            "Error: message too long (%zu bytes, max %.0ju bits)\n",
            password_len, (uintmax_t)max_bits);
        free(password);
        return alg;
    }
    //// 패스워드 끝

    //// salt 입력하는 부분
    char salt_input[8192];
    while (getchar() != '\n');
    printf("Enter salt (or hex): ");
    fgets(salt_input, sizeof salt_input, stdin);
    salt_input[strcspn(salt_input, "\n")] = 0;
    if (is_hex_string(salt_input)) {
        salt_len = strlen(salt_input) / 2;
        salt = (uint8_t*)malloc(salt_len);
        for (size_t i = 0; i < salt_len; ++i)
            salt[i] = hex2byte(salt_input[2 * i], salt_input[2 * i + 1]);
    }
    else {
        salt_len = strlen(salt_input);
        salt = (uint8_t*)malloc(salt_len);
        memcpy(salt, salt_input, salt_len);
    }
    if (salt_len == 0) {
        fprintf(stderr, "Error: key cannot be empty\n");
        free(salt);
        return alg;
    }
    if (salt_len > 8192) {
        fprintf(stderr, "Error: key too long (%zu bytes, max %zu bytes)\n",
            salt_len, max_digest_bytes);
        free(salt);
        return alg;
    }

    printf("Enter iteration count (e.g. 10000): ");
    scanf_s("%d", &iteration);
    if (iteration <= 0) {
        fprintf(stderr, "Error: iteration must be positive\n");
        free(password);
        free(salt);
        return alg;
    }
    size_t derivedKey_len = 0;
    printf("Enter desired derived key length (bytes): ");
    if (scanf_s("%zu", &derivedKey_len) != 1 || derivedKey_len == 0) {
        fprintf(stderr, "Error: invalid derived key length\n");
        return 1;
    }
    uint8_t* derivedKey = (uint8_t*)malloc(derivedKey_len);


    printf("Message       : %s\n", input);
    printf("Message Length: %zu bytes (%zu bits)\n", password_len, password_len * 8);
    printf("HMac Algorithm: %s\n", hash_name);
    printf("salt            : %s\n", salt_input);
    printf("salt Length     : %zu bytes (%zu bits)\n", salt_len, salt_len * 8);
    printf("iteration        : %d\n", iteration);
    printf("derivedKey Length    : %zu bytes (%zu bits)\n", derivedKey_len, derivedKey_len * 8);

    if (compute_PBKDF2(alg,
        max_digest_bytes,
        password,
        password_len,
        salt,
        salt_len,
        iteration,
        derivedKey,
        derivedKey_len) != 1)

    {

        fprintf(stderr, "Hash error\n");
        free(password);
        free(salt);
        free(derivedKey);
        return alg;
    }

    char* hexout = (char*)malloc(2 * derivedKey_len + 1);
    to_hex_string(derivedKey, derivedKey_len, hexout);

	printf("\n=========derived Key Information=========\n");
    printf("Message       : %s\n", input);
    printf("Message Length: %zu bytes (%zu bits)\n", password_len, password_len * 8);
    printf("HMac Algorithm: %s\n", hash_name);
	printf("salt            : %s\n", salt_input);
	printf("salt Length     : %zu bytes (%zu bits)\n", salt_len, salt_len * 8);
	printf("iteration        : %d\n", iteration);
    printf("derivedKey           : %s\n", hexout);
    printf("derivedKey Length    : %zu bytes (%zu bits)\n", derivedKey_len, derivedKey_len * 8);

    printf("\n");

    free(password);
    free(salt);
    free(derivedKey);
    return 0;
}
