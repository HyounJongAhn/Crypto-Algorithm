#pragma once
/* pbkdf2.h */
#ifndef HEADER_PBKDF_H
#define HEADER_PBKDF_H

#include <stddef.h>
#include <stdint.h>
#include "Mac.h"    // compute_HMac, HMacAlgorithm 선언
#include "Hash.h"

    /**
     * \brief PBKDF2‐HMAC‐SHA256 구현
     * \param password      비밀번호(바이트 배열)
     * \param passwordLen   비밀번호 길이(바이트)
     * \param salt          솔트(바이트 배열)
     * \param saltLen       솔트 길이(바이트)
     * \param iter          반복 횟수 (iteration count)
     * \param outKey        출력 키를 저장할 버퍼
     * \param outKeyLen     생성할 키의 길이(바이트)
     * \return 성공 시 1, 실패 시 0
     */
static bool is_hex_string(const char* s);
static uint8_t hex2byte(char hi, char lo);

int DoPBKDF(int num);
int compute_PBKDF2(
    HMacAlgorithm alg,
    size_t DIGEST_LEN,
    const uint8_t* password,
    size_t* passwordLen,
    const uint8_t* salt,
    size_t saltLen,
    int iter,
    uint8_t* outKey,
    int outKeyLen);


#endif /* pbkdf2.h */