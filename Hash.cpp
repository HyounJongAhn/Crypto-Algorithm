#define _CRT_SECURE_NO_WARNINGS
#include "Hash.h"
#include "util.h"
#include <string.h>
#include <format>

#include <cctype>
#include <iostream>
#define BUFFER_SIZE 1024*256
int choose_shake() {
    int SHAKE = 0;
    printf("Choose SHAKE Use or Unuse : \n");
    printf("0. USE\n");
	printf("1. UNUSE\n");
    printf("Input Number : ");
    if (scanf_s("%d", &SHAKE) != 1) {
        while (getchar() != '\n');
    }
    return SHAKE;
};

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
	case HASH_ALG_SHA3_224: {
        int shake = 0;
		shake = 2; // SHAKE 사용 안함
        sha3_hash(digest, KECCAK_SHA3_224 / 8, (uint8_t*)message, msg_len, KECCAK_SHA3_224, shake);
		*digest_len = KECCAK_SHA3_224 / 8;
		return 0;
	}
	case HASH_ALG_SHA3_256: {
        int shake = 0;
        shake = choose_shake();
        sha3_hash(digest, KECCAK_SHA3_256 / 8, (uint8_t*)message, msg_len, KECCAK_SHA3_256, shake);
        *digest_len = KECCAK_SHA3_256 / 8;
        return 0;
	}
	case HASH_ALG_SHA3_384: {
        int shake = 0;
		shake = 2; // SHAKE 사용 안함
        sha3_hash(digest, KECCAK_SHA3_384 / 8, (uint8_t*)message, msg_len, KECCAK_SHA3_384, shake);
        *digest_len = KECCAK_SHA3_384 / 8;
        return 0;
	}
	case HASH_ALG_SHA3_512: {
        int shake = 0;
		shake = 2; // SHAKE 사용 안함
        sha3_hash(digest, KECCAK_SHA3_512 / 8, (uint8_t*)message, msg_len, KECCAK_SHA3_512, shake);
        *digest_len = KECCAK_SHA3_512 / 8;
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
		getchar(); // 버퍼 비우기
		SHA224_Streaming(alg, max_digest_bytes);
        break;
    case 2: alg = HASH_ALG_SHA256; hash_name = "SHA-256";
        max_bits = (((uint64_t)1) << 64) - 1;
        max_digest_bytes = SHA256_DIGEST_SIZE;
        getchar(); // 버퍼 비우기
        SHA256_Streaming(alg, max_digest_bytes);
        break;
    case 3: alg = HASH_ALG_SHA384; hash_name = "SHA-384";
        max_bits = (((uint64_t)1) << 128) - 1;
        max_digest_bytes = SHA384_DIGEST_SIZE;
        getchar(); // 버퍼 비우기
        SHA384_Streaming(alg, max_digest_bytes);
        break;
    case 4: alg = HASH_ALG_SHA512; hash_name = "SHA-512";
        max_bits = (((uint64_t)1) << 128) - 1;
        max_digest_bytes = SHA512_DIGEST_SIZE;
        getchar(); // 버퍼 비우기
        SHA512_Streaming(alg, max_digest_bytes);
        break;
	case 5: alg = HASH_ALG_LSH256; hash_name = "LSH-256";
		max_bits = (((uint64_t)1) << 128) - 1;
		max_digest_bytes = LSH256_DIGEST_SIZE;
        getchar(); // 버퍼 비우기
        LSH256_Streaming(alg, max_digest_bytes);
		break;
	case 6: alg = HASH_ALG_LSH512; hash_name = "LSH-512";
		max_bits = (((uint64_t)1) << 128) - 1;
		max_digest_bytes = LSH512_DIGEST_SIZE;
        getchar(); // 버퍼 비우기
        LSH512_Streaming(alg, max_digest_bytes);
        break;
	case 7: alg = HASH_ALG_SHA3_224; hash_name = "SHA3-224";
		max_bits = (((uint64_t)1) << 64) - 1;
		max_digest_bytes = KECCAK_SHA3_224;
		break;
	case 8: alg = HASH_ALG_SHA3_256; hash_name = "SHA3-256";
		max_bits = (((uint64_t)1) << 64) - 1;
		max_digest_bytes = KECCAK_SHA3_256;
		break;
	case 9: alg = HASH_ALG_SHA3_384; hash_name = "SHA3-384";
		max_bits = (((uint64_t)1) << 128) - 1;
		max_digest_bytes = KECCAK_SHA3_384;
		break;
	case 10: alg = HASH_ALG_SHA3_512; hash_name = "SHA3-512";
		max_bits = (((uint64_t)1) << 128) - 1;
		max_digest_bytes = KECCAK_SHA3_512;
		break;
    default:
        fprintf(stderr, "Unknown algorithm\n");
        return HASH_ALG_UNKNOWN;
    }
    return alg;
}

void SHA224_Streaming(HashAlgorithm alg, int max_digest_bytes){

    size_t data_len = 0;
    char in_path[256];

    ask_input_file(in_path);

    FILE* fin = fopen(in_path, "rb");

    size_t total_read = 0;
    size_t bytes_read = 0;

    uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
    size_t last_padding = 0;  // 마지막 블록의 패딩 크기
    uint8_t inbuf[16];
    uint8_t digest[SHA224_DIGEST_SIZE];
    memset(digest,0, SHA224_DIGEST_SIZE);
    SHA224_CTX ctx;
    SHA224_Init(&ctx);

    while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
        size_t i = 0;

        while (i < bytes_read) {
            size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

            memcpy(inbuf, buffer + i, read_len);
            SHA224_Update(&ctx, inbuf, read_len);
            i += 16;  
        }
    }
    SHA224_Final(&ctx, digest);

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, max_digest_bytes, hexout);

    printf("Hash Algorithm: SHA-224\n");
    printf("Hash Value    : %s\n", hexout);

    free(hexout);
    free(buffer);
}

void SHA256_Streaming(HashAlgorithm alg, int max_digest_bytes) {

    size_t data_len = 0;
    char in_path[256];

    ask_input_file(in_path);

    FILE* fin = fopen(in_path, "rb");

    size_t total_read = 0;
    size_t bytes_read = 0;

    uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
    size_t last_padding = 0;  // 마지막 블록의 패딩 크기
    uint8_t inbuf[16];
    uint8_t digest[SHA256_DIGEST_SIZE];
    memset(digest, 0, SHA256_DIGEST_SIZE);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
        size_t i = 0;

        while (i < bytes_read) {
            size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

            memcpy(inbuf, buffer + i, read_len);
            SHA256_Update(&ctx, inbuf, read_len);
            i += 16;
        }
    }
    SHA256_Final(&ctx, digest);

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, max_digest_bytes, hexout);

    printf("Hash Algorithm: SHA-256\n");
    printf("Hash Value    : %s\n", hexout);

    free(hexout);
    free(buffer);
}

void SHA384_Streaming(HashAlgorithm alg, int max_digest_bytes) {

    size_t data_len = 0;
    char in_path[256];

    ask_input_file(in_path);

    FILE* fin = fopen(in_path, "rb");

    size_t total_read = 0;
    size_t bytes_read = 0;

    uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
    size_t last_padding = 0;  // 마지막 블록의 패딩 크기
    uint8_t inbuf[16];
    uint8_t digest[SHA384_DIGEST_SIZE];
    memset(digest, 0, SHA384_DIGEST_SIZE);
    SHA384_CTX ctx;
    SHA384_Init(&ctx);

    while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
        size_t i = 0;

        while (i < bytes_read) {
            size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

            memcpy(inbuf, buffer + i, read_len);
            SHA384_Update(&ctx, inbuf, read_len);
            i += 16;
        }
    }
    SHA384_Final(&ctx, digest);

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, max_digest_bytes, hexout);

    printf("Hash Algorithm: SHA-384\n");
    printf("Hash Value    : %s\n", hexout);

    free(hexout);
    free(buffer);
}

void SHA512_Streaming(HashAlgorithm alg, int max_digest_bytes) {

    size_t data_len = 0;
    char in_path[256];

    ask_input_file(in_path);

    FILE* fin = fopen(in_path, "rb");

    size_t total_read = 0;
    size_t bytes_read = 0;

    uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
    size_t last_padding = 0;  // 마지막 블록의 패딩 크기
    uint8_t inbuf[16];
    uint8_t digest[SHA512_DIGEST_SIZE];
    memset(digest, 0, SHA512_DIGEST_SIZE);
    SHA512_CTX ctx;
    SHA512_Init(&ctx);

    while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
        size_t i = 0;

        while (i < bytes_read) {
            size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

            memcpy(inbuf, buffer + i, read_len);
            SHA512_Update(&ctx, inbuf, read_len);
            i += 16;
        }
    }
    SHA512_Final(&ctx, digest);

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, max_digest_bytes, hexout);

    printf("Hash Algorithm: SHA-512\n");
    printf("Hash Value    : %s\n", hexout);

    free(hexout);
    free(buffer);
}

void LSH256_Streaming(HashAlgorithm alg, int max_digest_bytes) {

    size_t data_len = 0;
    char in_path[256];
    
    

    ask_input_file(in_path);

    FILE* fin = fopen(in_path, "rb");

    size_t total_read = 0;
    size_t bytes_read = 0;

    uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
    size_t last_padding = 0;  // 마지막 블록의 패딩 크기
    uint8_t inbuf[16];
    uint8_t digest[LSH256_DIGEST_SIZE];
    memset(digest, 0, LSH256_DIGEST_SIZE);
    LSH256_CTX ctx;
    LSH256_Init(&ctx);

    while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
        size_t i = 0;

        while (i < bytes_read) {
            size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

            memcpy(inbuf, buffer + i, read_len); 
            LSH256_Update(&ctx, (const uint8_t*)inbuf, read_len);
            i += 16;
        }
    }
    LSH256_Final(&ctx, digest);

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, max_digest_bytes, hexout);

    printf("Hash Algorithm: LSH-256\n");
    printf("Hash Value    : %s\n", hexout);

    free(hexout);
    free(buffer);
}

void LSH512_Streaming(HashAlgorithm alg, int max_digest_bytes) {

    size_t data_len = 0;
    char in_path[256];



    ask_input_file(in_path);

    FILE* fin = fopen(in_path, "rb");

    size_t total_read = 0;
    size_t bytes_read = 0;

    uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
    size_t last_padding = 0;  // 마지막 블록의 패딩 크기
    uint8_t inbuf[16];
    uint8_t digest[LSH512_DIGEST_SIZE];
    memset(digest, 0, LSH512_DIGEST_SIZE);
    LSH512_CTX ctx;
    LSH512_Init(&ctx);

    while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
        size_t i = 0;

        while (i < bytes_read) {
            size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

            memcpy(inbuf, buffer + i, read_len);
            LSH512_Update(&ctx, (const uint8_t*)inbuf, read_len);
            i += 16;
        }
    }
    LSH512_Final(&ctx, digest);

    char* hexout = (char*)malloc(2 * max_digest_bytes + 1);
    to_hex_string(digest, max_digest_bytes, hexout);

    printf("Hash Algorithm: LSH-512\n");
    printf("Hash Value    : %s\n", hexout);

    free(hexout);
    free(buffer);
}

