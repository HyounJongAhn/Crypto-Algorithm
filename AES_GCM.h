#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

typedef struct
{
    unsigned char* key;             // MasterKey
    size_t keySize;                 // MasterKey Size
    unsigned char* iv;              // Initial Vector 
    size_t ivSize;                  // Initial Vector Size 
    unsigned char* aad;             // Additional Authenticated Data 
    size_t aadSize;                 // Additional Authenticated Data Size 
    unsigned char tag[16];          // Tag 
    size_t tagSize;                 // TagSize
    unsigned char H[16];            // Calc H 
    size_t CLen;                    // Length of Cipher 
    unsigned char J0[16];           // J0 
    unsigned char lastBlock[16];
    size_t lastBlockSize;
} GCM_CTX;
// ----------------------------------------------------------------

void Encrypt_test(unsigned char* key, size_t keySize, unsigned char* input, unsigned char* output);

void GCTR_E(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output);
void GCTR_D(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output);
void GHASH(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize);
void mul_H(GCM_CTX* GCM_ctx, unsigned char* Y);

// ----------------------------------------------------------------

void GCM_Encrypt_init(                      // IV 설정 다하기 + GHASH(AAD)
    GCM_CTX* GCM_ctx,
    unsigned char* key,
    size_t keySize,
    unsigned char* iv,
    size_t ivSize,
    unsigned char* aad,
    size_t aadSize);

void GCM_Encrypt_update(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output, size_t outputSize); // 암호문 계속 업데이트
void GCM_Encrypt_final(GCM_CTX* GCM_ctx, unsigned char* tag); // Tag 나와야 함 

// ----------------------------------------------------------------

void GCM_Decrypt_init(
    GCM_CTX* GCM_ctx,
    unsigned char* key,
    size_t keySize,
    unsigned char* iv,
    size_t ivSize,
    unsigned char* aad,
    size_t aadSize);

void GCM_Decrypt_update(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output, size_t outputSize); // 복호화 + tag 계산
void GCM_Decrypt_final(GCM_CTX* GCM_ctx, unsigned char* tag, size_t tagSize); // Tag 검증