#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <ctype.h>
#include <stdexcept>
#define NONCE_SIZE 12
#define BLOCK_SIZE 16
typedef enum {
    OPERATIONMODE_CBC,
    OPERATIONMODE_CTR,
    OPERATIONMODE_ECB,
    OPERATIONMODE_GCM
} OperationMode;

void xorBlocks(uint8_t* block1, uint8_t* block2, uint8_t* result);
void get_nonce_from_IV(uint8_t* iv, uint8_t* nonce);
void input_key(uint8_t* Key);
void incrementCounter(uint8_t* counter);
void GHASH(uint8_t* input, size_t length, uint8_t* H, uint8_t* result);
void updateGHASH(uint8_t* block, uint8_t* H);
void incrementNonce(uint8_t* counter);
void input_tag(uint8_t* tag);
// ������ �Է� �ޱ� (�ִ� 2048KB���� ó�� ����)
void input_data(uint8_t* data, size_t* data_len);

// IV �Է� �ޱ� (�ִ� 16����Ʈ, 16������ �Է�)
void input_iv(uint8_t* iv);