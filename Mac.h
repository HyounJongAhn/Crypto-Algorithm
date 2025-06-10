#pragma once
/* Mac.h */
#ifndef MAC_H
#define MAC_H

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
#include "hash.h"



/// 지원하는 알고리즘 종류
typedef enum {
    HMAC_ALG_SHA224,
    HMAC_ALG_SHA256,
    HMAC_ALG_SHA384,
    HMAC_ALG_SHA512,
    HMAC_ALG_UNKNOWN
} HMacAlgorithm;
static bool is_hex_string(const char* s);
static uint8_t hex2byte(char hi, char lo);


/**
 * 메시지에 대해 지정한 알고리즘으로 해시를 계산
 * @param alg          사용할 알고리즘
 * @param message      NULL-terminated 입력 메시지
 * @param digest       (출력) 해시 바이트를 받을 버퍼
 * @param digest_len   (출력) 실제 해시 길이(바이트 단위)
 * @return 0 on success, -1 if alg==HASH_ALG_UNKNOWN
 */
int compute_HMac(HMacAlgorithm alg,
    const char* message,
    size_t msg_len,
    const char* key,
    size_t key_len,
    uint8_t* digest,
    size_t* digest_len);

HMacAlgorithm DoHMac(int num);

#endif /* MAC_H */
