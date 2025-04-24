#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <iostream>
#include "ARIA.h"
#include "LEA.h"
#include "AES.h"
typedef enum {
    BLCKCIPHER_ALG_AES128,
    BLCKCIPHER_ALG_AES192,
    BLCKCIPHER_ALG_AES256,
    BLCKCIPHER_ALG_ARIA128,
    BLCKCIPHER_ALG_ARIA192,
    BLCKCIPHER_ALG_ARIA256,
    BLCKCIPHER_ALG_LEA128,
    BLCKCIPHER_ALG_LEA192,
    BLCKCIPHER_ALG_LEA256
} BlockCipher;
#define MAX_INPUT_SIZE 2048 * 1024
#define CHUNK_SIZE 1024
#define BLOCK_SIZE 16
uint8_t* AES_128_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* AES_128_Decrypt(uint8_t* key, uint8_t* data);
uint8_t* AES_192_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* AES_192_Decrypt(uint8_t* key, uint8_t* data);
uint8_t* AES_256_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* AES_256_Decrypt(uint8_t* key, uint8_t* data);

uint8_t* ARIA_128_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* ARIA_128_Decrypt(uint8_t* key, uint8_t* data);
uint8_t* ARIA_192_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* ARIA_192_Decrypt(uint8_t* key, uint8_t* data);
uint8_t* ARIA_256_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* ARIA_256_Decrypt(uint8_t* key, uint8_t* data);

uint8_t* LEA_128_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* LEA_128_Decrypt(uint8_t* key, uint8_t* data);
uint8_t* LEA_192_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* LEA_192_Decrypt(uint8_t* key, uint8_t* data);
uint8_t* LEA_256_Encrypt(uint8_t* key, uint8_t* data);
uint8_t* LEA_256_Decrypt(uint8_t* key, uint8_t* data);


void ARIA_test();
void LEA_test();