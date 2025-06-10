#include "AES_GCM.h"
#include "Fast_AES.h"

void Encrypt_test(unsigned char* key, size_t keySize, unsigned char* input, unsigned char* output)
{
    AES_Encryption(input, key, keySize, output);
}

void mul_H(GCM_CTX* GCM_ctx, unsigned char* Y)
{
    unsigned char Z[16] = { 0, };
    unsigned char V[16] = { 0, };
    for (int i = 0; i < 16; i++) V[i] = GCM_ctx->H[i];

    unsigned char R = 0xe1;

    for (int i = 0; i < 128; i++) {
        int byte_index = i / 8;
        int bit_index = 7 - (i % 8);

        if ((Y[byte_index] >> bit_index) & 1)
        {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }

        int carry = V[15] & 1;
        for (int j = 15; j >= 0; j--) {
            int new_carry = V[j] & 1;
            V[j] = (V[j] >> 1) | ((j > 0 ? (V[j - 1] & 1) : 0) << 7);
        }

        // XOR with R if LSB was 1
        if (carry) {
            V[0] ^= R;
        }
    }

    for (int i = 0; i < 16; i++) Y[i] = Z[i];
}


void GCTR_E(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output)
{
    unsigned char block[16] = { 0, };
    unsigned char temp[16] = { 0, };
    for (int i = 0; i < 16; i++) block[i] = GCM_ctx->iv[i];
    Encrypt_test(GCM_ctx->key, GCM_ctx->keySize, block, temp);    // 원하는 암호 알고리즘으로 수정
    for (int i = 0; i < inputSize; i++) output[i] = temp[i] ^ input[i];

    for (int j = 15; j >= 12; j--)
    {
        GCM_ctx->iv[j]++;
        if (GCM_ctx->iv[j]) break;
    }

    if (inputSize == 16)
    {
        GHASH(GCM_ctx, output, 16);
    }

    if (inputSize != 16)
    {
        size_t padSize = 16 - inputSize;
        for (int i = 0; i < padSize; i++) output[15 - i] = 0;
        GHASH(GCM_ctx, output, 16);
    }

    GCM_ctx->CLen += inputSize;
}


void GCTR_D(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output)
{
    if (inputSize == 16)
    {
        GHASH(GCM_ctx, input, 16);
    }

    if (inputSize != 16)
    {
        unsigned char temp[16] = { 0, };
        memcpy(temp, input, inputSize);
        // size_t padSize = 16 - inputSize; 
        // for (int i = 0; i < padSize; i++) temp[15 - i] = 0;
        GHASH(GCM_ctx, temp, 16);
    }

    GCM_ctx->CLen += inputSize;

    unsigned char block[16] = { 0, };
    unsigned char temp[16] = { 0, };
    for (int i = 0; i < 16; i++) block[i] = GCM_ctx->iv[i];
    Encrypt_test(GCM_ctx->key, GCM_ctx->keySize, block, temp);    // 원하는 암호 알고리즘으로 수정

    for (int i = 0; i < inputSize; i++) output[i] ^= temp[i] ^ input[i];
    for (int j = 15; j >= 12; j--)
    {
        GCM_ctx->iv[j]++;
        if (GCM_ctx->iv[j]) break;
    }
}


void GHASH(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize)
{
    unsigned char Y[16] = { 0, };
    for (int i = 0; i < 16; i++) Y[i] = GCM_ctx->tag[i];

    for (int i = 0; i < inputSize; i += 16)
    {
        Y[0] ^= input[i + 0];  Y[1] ^= input[i + 1];  Y[2] ^= input[i + 2];  Y[3] ^= input[i + 3];
        Y[4] ^= input[i + 4];  Y[5] ^= input[i + 5];  Y[6] ^= input[i + 6];  Y[7] ^= input[i + 7];
        Y[8] ^= input[i + 8];  Y[9] ^= input[i + 9];  Y[10] ^= input[i + 10]; Y[11] ^= input[i + 11];
        Y[12] ^= input[i + 12]; Y[13] ^= input[i + 13]; Y[14] ^= input[i + 14]; Y[15] ^= input[i + 15];
        mul_H(GCM_ctx, Y);
    }

    for (int i = 0; i < 16; i++) GCM_ctx->tag[i] = Y[i];

    return;
}

// ---------------------------------------------------------------------------------------------

void GCM_Encrypt_init(      // IV 설정 다하기 + GHASH(AAD)
    GCM_CTX* GCM_ctx,
    unsigned char* key,
    size_t keySize,
    unsigned char* iv,
    size_t ivSize,
    unsigned char* aad,
    size_t aadSize)
{
    GCM_ctx->key = key;             // key Setting 
    GCM_ctx->keySize = keySize;

    GCM_ctx->iv = iv;               // IV Setting 
    GCM_ctx->ivSize = ivSize;

    GCM_ctx->aad = aad;             // AAD Setting 
    GCM_ctx->aadSize = aadSize;

    for (int i = 0; i < 16; i++) GCM_ctx->tag[i] = 0;             // tag Setting 
    GCM_ctx->tagSize = 16;

    GCM_ctx->CLen = 0;              // tag 생성을 위한 암호문 길이 초기화 
    GCM_ctx->lastBlockSize = 0;     // 

    for (int i = 0; i < 16; i++) GCM_ctx->H[i] = 0;          // GHASH에 필요한 H 값 초기화 
    for (int i = 0; i < 16; i++) GCM_ctx->J0[i] = 0;         // tag 생성에 필요한 J0 값 초기화 
    for (int i = 0; i < 16; i++) GCM_ctx->lastBlock[i] = 0;  // 마지막 블록 기록

    // H 계산해야함 
    unsigned char temp_H[16] = { 0 };
    Encrypt_test(GCM_ctx->key, GCM_ctx->keySize, GCM_ctx->H, temp_H);
    for (int i = 0; i < 16; i++) GCM_ctx->H[i] = temp_H[i];

    // iv Setting 
    unsigned char* j0 = NULL;

    if (GCM_ctx->ivSize == 12)
    {
        j0 = (unsigned char*)calloc(ivSize + 4, sizeof(unsigned char));
        memcpy(j0, iv, ivSize);
        j0[ivSize + 3] = 1;

        for (int i = 0; i < 16; i++)
        {
            GCM_ctx->iv[i] = j0[i];
            GCM_ctx->J0[i] = j0[i];
        }

        for (int i = 15; i >= 12; i--)
        {
            GCM_ctx->iv[i]++;
            if (GCM_ctx->iv[i]) break;
        }
        free(j0);
    }

    if (GCM_ctx->ivSize != 12)
    {
        size_t padSize = (16 - (ivSize - (ivSize / 16) * 16)) % 16;
        size_t ivBitSize = ivSize * 8;
        j0 = (unsigned char*)calloc(ivSize + padSize + 8 + 8, sizeof(unsigned char));

        memcpy(j0, iv, ivSize);

        j0[ivSize + padSize + 8] = ((unsigned char)((ivBitSize >> 56) & 0xff));
        j0[ivSize + padSize + 9] = ((unsigned char)((ivBitSize >> 48) & 0xff));
        j0[ivSize + padSize + 10] = ((unsigned char)((ivBitSize >> 40) & 0xff));
        j0[ivSize + padSize + 11] = ((unsigned char)((ivBitSize >> 32) & 0xff));
        j0[ivSize + padSize + 12] = ((unsigned char)((ivBitSize >> 24) & 0xff));
        j0[ivSize + padSize + 13] = ((unsigned char)((ivBitSize >> 16) & 0xff));
        j0[ivSize + padSize + 14] = ((unsigned char)((ivBitSize >> 8) & 0xff));
        j0[ivSize + padSize + 15] = ((unsigned char)(ivBitSize & 0xff));

        GHASH(GCM_ctx, j0, ivSize + padSize + 8 + 8);

        for (int i = 0; i < 16; i++)
        {
            GCM_ctx->iv[i] = GCM_ctx->tag[i];
            GCM_ctx->J0[i] = GCM_ctx->tag[i];
        }
    }

    for (int j = 15; j >= 12; j--)
    {
        GCM_ctx->iv[j]++;
        if (GCM_ctx->iv[j]) break;
    }

    // AAD Setting 
    unsigned char* temp_tag;
    size_t padSize = 16 - (aadSize - (aadSize / 16) * 16);
    temp_tag = (unsigned char*)calloc(padSize + aadSize, sizeof(unsigned char));

    memcpy(temp_tag, GCM_ctx->aad, aadSize);

    for (int i = 0; i < 16; i++)
    {
        GCM_ctx->tag[i] = 0;
    }

    GHASH(GCM_ctx, temp_tag, padSize + aadSize);
    free(temp_tag);

    return;
}


void GCM_Encrypt_update(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output, size_t outputSize)
{
    GCM_ctx->lastBlockSize += inputSize & 0x0f;
    for (int i = 0; i < inputSize - GCM_ctx->lastBlockSize; i += 16)
    {
        GCTR_E(GCM_ctx, input + i, 16, output + i);
    }

    if (GCM_ctx->lastBlockSize) GCTR_E(GCM_ctx, input + inputSize - GCM_ctx->lastBlockSize, GCM_ctx->lastBlockSize, output + inputSize - GCM_ctx->lastBlockSize);

    return;
}

void GCM_Encrypt_final(GCM_CTX* GCM_ctx, unsigned char* tag)
{
    unsigned char block[16] = { 0, };
    size_t aadBitSize = GCM_ctx->aadSize * 8;
    block[0] = ((unsigned char)(aadBitSize >> 56));
    block[1] = ((unsigned char)(aadBitSize >> 48));
    block[2] = ((unsigned char)(aadBitSize >> 40));
    block[3] = ((unsigned char)(aadBitSize >> 32));
    block[4] = ((unsigned char)(aadBitSize >> 24));
    block[5] = ((unsigned char)(aadBitSize >> 16));
    block[6] = ((unsigned char)(aadBitSize >> 8));
    block[7] = ((unsigned char)(aadBitSize));

    size_t CBitSize = GCM_ctx->CLen * 8;
    block[8] = ((unsigned char)(CBitSize >> 56));
    block[9] = ((unsigned char)(CBitSize >> 48));
    block[10] = ((unsigned char)(CBitSize >> 40));
    block[11] = ((unsigned char)(CBitSize >> 32));
    block[12] = ((unsigned char)(CBitSize >> 24));
    block[13] = ((unsigned char)(CBitSize >> 16));
    block[14] = ((unsigned char)(CBitSize >> 8));
    block[15] = ((unsigned char)(CBitSize));

    GHASH(GCM_ctx, block, 16);

    unsigned char temp[16] = { 0 };
    Encrypt_test(GCM_ctx->key, GCM_ctx->keySize, GCM_ctx->J0, temp);  // 원하는 암호 알고리즘으로 수정
    for (int i = 0; i < 16; i++) GCM_ctx->tag[i] ^= temp[i];
    for (int i = 0; i < 16; i++) tag[i] = GCM_ctx->tag[i];
}

// ---------------------------------------------------------------------------------------------

void GCM_Decrypt_init(
    GCM_CTX* GCM_ctx,
    unsigned char* key,
    size_t keySize,
    unsigned char* iv,
    size_t ivSize,
    unsigned char* aad,
    size_t aadSize)
{
    GCM_ctx->key = key;             // key Setting 
    GCM_ctx->keySize = keySize;

    GCM_ctx->iv = iv;               // IV Setting 
    GCM_ctx->ivSize = ivSize;

    GCM_ctx->aad = aad;             // AAD Setting 
    GCM_ctx->aadSize = aadSize;

    for (int i = 0; i < 16; i++) GCM_ctx->tag[i] = 0;             // tag Setting 
    GCM_ctx->tagSize = 16;

    GCM_ctx->CLen = 0;              // tag 생성을 위한 암호문 길이 초기화 
    GCM_ctx->lastBlockSize = 0;     // 

    for (int i = 0; i < 16; i++) GCM_ctx->H[i] = 0;          // GHASH에 필요한 H 값 초기화 
    for (int i = 0; i < 16; i++) GCM_ctx->J0[i] = 0;         // tag 생성에 필요한 J0 값 초기화 
    for (int i = 0; i < 16; i++) GCM_ctx->lastBlock[i] = 0;  // 마지막 블록 기록

    // H 계산해야함 
    unsigned char temp_H[16] = { 0 };
    Encrypt_test(GCM_ctx->key, GCM_ctx->keySize, GCM_ctx->H, temp_H);
    for (int i = 0; i < 16; i++) GCM_ctx->H[i] = temp_H[i];

    // iv Setting 
    unsigned char* j0 = NULL;

    if (GCM_ctx->ivSize == 12)
    {
        j0 = (unsigned char*)calloc(ivSize + 4, sizeof(unsigned char));
        memcpy(j0, iv, ivSize);
        j0[ivSize + 3] = 1;

        for (int i = 0; i < 16; i++)
        {
            GCM_ctx->iv[i] = j0[i];
            GCM_ctx->J0[i] = j0[i];
        }

        for (int i = 15; i >= 12; i--)
        {
            GCM_ctx->iv[i]++;
            if (GCM_ctx->iv[i]) break;
        }
        free(j0);
    }

    if (GCM_ctx->ivSize != 12)
    {
        size_t padSize = (16 - (ivSize - (ivSize / 16) * 16)) % 16;
        size_t ivBitSize = ivSize * 8;
        j0 = (unsigned char*)calloc(ivSize + padSize + 8 + 8, sizeof(unsigned char));

        memcpy(j0, iv, ivSize);

        j0[ivSize + padSize + 8] = ((unsigned char)((ivBitSize >> 56) & 0xff));
        j0[ivSize + padSize + 9] = ((unsigned char)((ivBitSize >> 48) & 0xff));
        j0[ivSize + padSize + 10] = ((unsigned char)((ivBitSize >> 40) & 0xff));
        j0[ivSize + padSize + 11] = ((unsigned char)((ivBitSize >> 32) & 0xff));
        j0[ivSize + padSize + 12] = ((unsigned char)((ivBitSize >> 24) & 0xff));
        j0[ivSize + padSize + 13] = ((unsigned char)((ivBitSize >> 16) & 0xff));
        j0[ivSize + padSize + 14] = ((unsigned char)((ivBitSize >> 8) & 0xff));
        j0[ivSize + padSize + 15] = ((unsigned char)(ivBitSize & 0xff));

        GHASH(GCM_ctx, j0, ivSize + padSize + 8 + 8);

        for (int i = 0; i < 16; i++)
        {
            GCM_ctx->iv[i] = GCM_ctx->tag[i];
            GCM_ctx->J0[i] = GCM_ctx->tag[i];
        }
    }

    for (int j = 15; j >= 12; j--)
    {
        GCM_ctx->iv[j]++;
        if (GCM_ctx->iv[j]) break;
    }

    // AAD Setting 
    unsigned char* temp_tag;
    size_t padSize = 16 - (aadSize - (aadSize / 16) * 16);
    temp_tag = (unsigned char*)calloc(padSize + aadSize, sizeof(unsigned char));

    memcpy(temp_tag, GCM_ctx->aad, aadSize);

    for (int i = 0; i < 16; i++)
    {
        GCM_ctx->tag[i] = 0;
    }

    GHASH(GCM_ctx, temp_tag, padSize + aadSize);
    free(temp_tag);
}

void GCM_Decrypt_update(GCM_CTX* GCM_ctx, unsigned char* input, size_t inputSize, unsigned char* output, size_t outputSize)
{
    GCM_ctx->lastBlockSize += inputSize & 0x0f;
    for (int i = 0; i < inputSize - GCM_ctx->lastBlockSize; i += 16)
    {
        GCTR_D(GCM_ctx, input + i, 16, output + i);
    }

    if (GCM_ctx->lastBlockSize) GCTR_D(GCM_ctx, input + inputSize - GCM_ctx->lastBlockSize, GCM_ctx->lastBlockSize, output + inputSize - GCM_ctx->lastBlockSize);

    return;
}

void GCM_Decrypt_final(GCM_CTX* GCM_ctx, unsigned char* tag, size_t tagSize)
{
    unsigned char block[16] = { 0, };
    size_t aadBitSize = GCM_ctx->aadSize * 8;
    block[0] = ((unsigned char)(aadBitSize >> 56));
    block[1] = ((unsigned char)(aadBitSize >> 48));
    block[2] = ((unsigned char)(aadBitSize >> 40));
    block[3] = ((unsigned char)(aadBitSize >> 32));
    block[4] = ((unsigned char)(aadBitSize >> 24));
    block[5] = ((unsigned char)(aadBitSize >> 16));
    block[6] = ((unsigned char)(aadBitSize >> 8));
    block[7] = ((unsigned char)(aadBitSize));

    size_t CBitSize = GCM_ctx->CLen * 8;
    block[8] = ((unsigned char)(CBitSize >> 56));
    block[9] = ((unsigned char)(CBitSize >> 48));
    block[10] = ((unsigned char)(CBitSize >> 40));
    block[11] = ((unsigned char)(CBitSize >> 32));
    block[12] = ((unsigned char)(CBitSize >> 24));
    block[13] = ((unsigned char)(CBitSize >> 16));
    block[14] = ((unsigned char)(CBitSize >> 8));
    block[15] = ((unsigned char)(CBitSize));

    GHASH(GCM_ctx, block, 16);

    unsigned char temp[16] = { 0 };
    Encrypt_test(GCM_ctx->key, GCM_ctx->keySize, GCM_ctx->J0, temp);  // 원하는 암호 알고리즘으로 수정
    for (int i = 0; i < 16; i++) GCM_ctx->tag[i] ^= temp[i];

    for (int i = 0; i < tagSize; i++)
    {
        if (GCM_ctx->tag[i] != tag[i])
        {
            printf("Invalid Tag\n");
            return;
        }
    }

    printf("Valid Tag\n");
    return;
}