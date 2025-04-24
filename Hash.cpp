/* hash.c */
#include "hash.h"

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


int compute_hash(HashAlgorithm alg,
    const char* message,
    uint8_t* digest,
    size_t* digest_len,
    size_t msg_len)
{
    switch (alg) {
    case HASH_ALG_SHA224: {
        SHA224_CTX ctx;
        SHA224_Init(&ctx);
        SHA224_Update(&ctx, message, msg_len);
        SHA224_Final(&ctx, digest);
        *digest_len = SHA224_DIGEST_SIZE;
        return 0;
    }
    case HASH_ALG_SHA256: {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, message, msg_len);
        SHA256_Final(&ctx, digest);
        *digest_len = SHA256_DIGEST_SIZE;
        return 0;
    }
    case HASH_ALG_SHA384: {
        SHA384_CTX ctx;
        SHA384_Init(&ctx);
        SHA384_Update(&ctx, message, msg_len);
        SHA384_Final(&ctx, digest);
        *digest_len = SHA384_DIGEST_SIZE;
        return 0;
    }
    case HASH_ALG_SHA512: {
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, message, msg_len);
        SHA512_Final(&ctx, digest);
        *digest_len = SHA512_DIGEST_SIZE;
        return 0;
    }
    case HASH_ALG_LSH256: {
        LSH256_CTX ctx;
        LSH256_Init(&ctx);
        LSH256_Update(&ctx, (const uint8_t*)message, msg_len);
        LSH256_Final(&ctx, digest);
        *digest_len = LSH256_DIGEST_SIZE;
        return 0;
    }
    case HASH_ALG_LSH512: {
        LSH512_CTX ctx;
        LSH512_Init(&ctx);
        LSH512_Update(&ctx, (const uint8_t*)message, msg_len);
        LSH512_Final(&ctx, digest);
        *digest_len = LSH512_DIGEST_SIZE;
        return 0;
    }
    default:
        return -1;
    }
}

void to_hex_string(const uint8_t* data,
    size_t len,
    char* hexstr)
{
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        hexstr[2 * i] = hex_digits[(data[i] >> 4) & 0xF];
        hexstr[2 * i + 1] = hex_digits[data[i] & 0xF];
    }
    hexstr[2 * len] = '\0';
}
HashAlgorithm DoHash(int num)
{
    HashAlgorithm alg;
    const char* hash_name;
    uint8_t* data;
    size_t       data_len;
    size_t       max_digest_bytes;


    uint64_t max_bits;

    
    switch (num) {
    case 1: alg = HASH_ALG_SHA224; hash_name = "SHA-224";
        max_bits = (((uint64_t)1) << 64) - 1;
        max_digest_bytes = SHA224_DIGEST_SIZE;
        break;
    case 2: alg = HASH_ALG_SHA256; hash_name = "SHA-256";
        max_bits = (((uint64_t)1) << 64) - 1;
        max_digest_bytes = SHA256_DIGEST_SIZE;
        break;
    case 3: alg = HASH_ALG_SHA384; hash_name = "SHA-384";
        max_bits = (((uint64_t)1) << 128) - 1;
        max_digest_bytes = SHA384_DIGEST_SIZE;
        break;
    case 4: alg = HASH_ALG_SHA512; hash_name = "SHA-512";
        max_bits = (((uint64_t)1) << 128) - 1;
        max_digest_bytes = SHA512_DIGEST_SIZE;
        break;
	case 5: alg = HASH_ALG_LSH256; hash_name = "LSH-256";
		max_bits = (((uint64_t)1) << 128) - 1;
		max_digest_bytes = LSH256_DIGEST_SIZE;
		break;
	case 6: alg = HASH_ALG_LSH512; hash_name = "LSH-512";
		max_bits = (((uint64_t)1) << 128) - 1;
		max_digest_bytes = LSH512_DIGEST_SIZE;
    default:
        fprintf(stderr, "Unknown algorithm\n");
        return HASH_ALG_UNKNOWN;
    }
    
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

    uint8_t* digest = (uint8_t*)malloc(max_digest_bytes);
    size_t   digest_len;
    if (compute_hash(alg,
        (const char*)data,
        digest,
        &digest_len, data_len) != 0)
    {
        fprintf(stderr, "Hash error\n");
        free(data);
        free(digest);
        return alg;
    }

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, digest_len, hexout);
    printf("Message       : %s\n", input);
    printf("Message Length: %zu bytes (%zu bits)\n",
        data_len, data_len * 8);
    printf("Hash Algorithm: %s\n", hash_name);
    printf("Hash Value    : %s\n", hexout);

    free(data);
    free(digest);
    free(hexout);
    return alg;
}