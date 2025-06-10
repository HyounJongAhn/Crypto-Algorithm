#pragma once
#ifndef RSA_PSS_H
#define RSA_PSS_H

#include <stddef.h>
#include <stdint.h>
#include "rsa.h"

#ifdef __cplusplus
extern "C" {
#endif
    static int mgf1(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len);
    int rsa_pss_sign(rsa_context* ctx,
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len);

    int rsa_pss_verify(rsa_context* ctx,
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif // RSA_PSS_H
