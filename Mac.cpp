/* Mac.c */
#include "Hash.h"
#include "Mac.h"
#include <string.h>
#include <format>
#include <cctype>
#include <iostream>
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

int compute_HMac(HMacAlgorithm alg,
    const char* message,
    size_t msg_len,
    const char* key,
    size_t key_len,
    uint8_t* digest,
    size_t* digest_len)
{
    switch (alg) {
    case HMAC_ALG_SHA224: {
        SHA224_CTX ctx;
        SHA224_HMAC_Init(&ctx, key , key_len);
        SHA224_HMAC_Update(&ctx, message, msg_len);
        SHA224_HMAC_Final(&ctx, key, key_len, digest);
        *digest_len = SHA224_DIGEST_SIZE;
        return 0;
    }
    case HMAC_ALG_SHA256: {
        SHA256_CTX ctx;
        SHA256_HMAC_Init(&ctx, key, key_len);
        SHA256_HMAC_Update(&ctx, message, msg_len);
        SHA256_HMAC_Final(&ctx, key, key_len, digest);
        *digest_len = SHA256_DIGEST_SIZE;
        return 0;
    }
    case HMAC_ALG_SHA384: {
        SHA384_CTX ctx;
        SHA384_HMAC_Init(&ctx, key, key_len);
        SHA384_HMAC_Update(&ctx, message, msg_len);
        SHA384_HMAC_Final(&ctx, key, key_len, digest);
        *digest_len = SHA384_DIGEST_SIZE;
        return 0;
    }
    case HMAC_ALG_SHA512: {
        SHA512_CTX ctx;
        SHA512_HMAC_Init(&ctx, key, key_len);
        SHA512_HMAC_Update(&ctx, message, msg_len);
        SHA512_HMAC_Final(&ctx, key, key_len, digest);
        *digest_len = SHA512_DIGEST_SIZE;
        return 0;
    }
    default:
        return -1;
    }
}

HMacAlgorithm DoHMac(int num)
{
    HMacAlgorithm alg;
    const char* hash_name;
    uint8_t* data;
    uint8_t* key;
    size_t       data_len;
    size_t       key_len;
    size_t       max_digest_bytes;


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

    //// 메시지 입력하는 부분
    char input[4096];
    while (getchar() != '\n');
    printf("Enter message (or hex): ");
    fgets(input, sizeof input, stdin);

    input[strcspn(input, "\n")] = 0;

    if (is_hex_string(input)) {
        data_len = strlen(input) / 2;
        data = (uint8_t*)malloc(data_len);
        for (size_t i = 0; i < data_len; ++i)
            data[i] = hex2byte(input[2 * i], input[2 * i + 1]);
    }
    else {
        data_len = strlen(input);
        data = (uint8_t*)malloc(data_len);
        memcpy(data, input, data_len);
    }

    uint64_t bits = (uint64_t)data_len * 8;
    if (bits > max_bits) {
        fprintf(stderr,
            "Error: message too long (%zu bytes, max %.0ju bits)\n",
            data_len, (uintmax_t)max_bits);
        free(data);
        return alg;
    }
    //// 메시지 입력 끝

    //// 키 입력하는 부분
	char key_input[4096];
	while (getchar() != '\n');
	printf("Enter key (or hex): ");
	fgets(key_input, sizeof key_input, stdin);
	key_input[strcspn(key_input, "\n")] = 0;
	if (is_hex_string(key_input)) {
		key_len = strlen(key_input) / 2;
		key = (uint8_t*)malloc(key_len);
		for (size_t i = 0; i < key_len; ++i)
			key[i] = hex2byte(key_input[2 * i], key_input[2 * i + 1]);
	}
	else {
		key_len = strlen(key_input);
		key = (uint8_t*)malloc(key_len);
		memcpy(key, key_input, key_len);
	}
	if (key_len == 0) {
		fprintf(stderr, "Error: key cannot be empty\n");
		free(key);
		return alg;
	}
	if (key_len > max_digest_bytes) {
		fprintf(stderr, "Error: key too long (%zu bytes, max %zu bytes)\n",
			key_len, max_digest_bytes);
		free(key);
		return alg;
	}

    uint8_t* digest = (uint8_t*)malloc(max_digest_bytes);
    size_t   digest_len;
    if (compute_HMac(alg,
        (const char*)data,
        data_len,
        (const char*)key,
        key_len,
        digest,
        &digest_len) != 0)
    {
        fprintf(stderr, "Hash error\n");
        free(key);
        free(data);
        free(digest);
        return alg;
    }

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, digest_len, hexout);

    printf("Message       : %s\n", input);
    printf("Message Length: %zu bytes (%zu bits)\n", data_len, data_len * 8);
	printf("Key           : %s\n", key_input);
	printf("Key Length    : %zu bytes (%zu bits)\n", key_len, key_len * 8);
    printf("HMac Algorithm: %s\n", hash_name);
    printf("HMac Value    : %s\n", hexout);
	printf("\n");
	free(key);
    free(data);
    free(digest);
    free(hexout);
    return alg;
}