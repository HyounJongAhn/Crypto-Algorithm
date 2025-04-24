/* hash.h */
#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
/* SHA‑224 */
#include "sha224.h"       /* #define SHA224_HASH_SIZE 28 */
/* SHA‑256 */
#include "sha256.h"       /* #define SHA256_DIGEST_SIZE 32 */
/* SHA‑384 */
#include "sha384.h"       /* #define SHA384_DIGEST_SIZE 48 */
/* SHA‑512 */
#include "sha512.h"       /* #define SHA512_DIGEST_SIZE 64 */
#include "lsh256.h"       /* #define LSH256_DIGEST_SIZE 32 */
#include "lsh512.h"       /* #define LSH512_DIGEST_SIZE 64 */


/// 지원하는 알고리즘 종류
typedef enum {
    HASH_ALG_LSH256,
    HASH_ALG_LSH512,
    HASH_ALG_SHA224,
    HASH_ALG_SHA256,
    HASH_ALG_SHA384,
    HASH_ALG_SHA512,
    HASH_ALG_UNKNOWN
} HashAlgorithm;

static bool is_hex_string(const char* s);

/**
 * 메시지에 대해 지정한 알고리즘으로 해시를 계산
 * @param alg          사용할 알고리즘
 * @param message      NULL-terminated 입력 메시지
 * @param digest       (출력) 해시 바이트를 받을 버퍼
 * @param digest_len   (출력) 실제 해시 길이(바이트 단위)
 * @return 0 on success, -1 if alg==HASH_ALG_UNKNOWN
 */
int compute_hash(HashAlgorithm alg,
    const char* message,
    uint8_t* digest,
    size_t* digest_len,
    size_t msg_len);

/**
 * 바이트 배열을 소문자 16진수 문자열로 변환
 * @param data     변환할 바이트 배열
 * @param len      배열 길이
 * @param hexstr   (출력) 2*len + 1 크기 이상인 버퍼
 */
void to_hex_string(const uint8_t* data,size_t len, char* hexstr);
HashAlgorithm DoHash(int num);

#endif /* HASH_H */
