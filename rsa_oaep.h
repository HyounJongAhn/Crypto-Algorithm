#pragma once
#ifndef RSA_OAEP_H
#define RSA_OAEP_H

#include <stddef.h>
#include <stdint.h>
#include "rsa.h" // 기존 rsa_context 정의

#ifdef __cplusplus
extern "C" {
#endif
    static int mgf1(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len);
    int rsa_oaep_encrypt(rsa_context* ctx,
        const uint8_t* input, size_t input_len,
        uint8_t* output, size_t* output_len);

    int rsa_oaep_decrypt(rsa_context* ctx,
        const uint8_t* input, size_t input_len,
        uint8_t* output, size_t* output_len);

#ifdef __cplusplus
}
#endif

#endif // RSA_OAEP_H
