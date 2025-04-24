#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <string>
#define MAX_INPUT_SIZE 2048 * 1024
#define CHUNK_SIZE 1024

#define AES128 1
#define AES192 2
#define AES256 3
#define ARIA128 4
#define ARIA192 5
#define ARIA256 6
#define LEA128 7
#define LEA192 8
#define LEA256 9

#define CBC 11
#define CTR 12
#define ECB 13
#define GCM 14
#define NONE 15

void Encrypt(int OperateModeNum, int BlockCiphernum);



