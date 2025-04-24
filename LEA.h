#ifndef _LEA_H_
#define _LEA_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // uint8_t, uint32_t »ç¿ë

typedef uint8_t BYTE;  // 1 byte
typedef uint32_t WORD; // 4 byte

int ROL(int i, WORD value);
int ROR(int i, WORD value);
void LEA_Key_128(BYTE* K, WORD* RK);
void LEA_Key_192(BYTE* K, WORD* RK);
void LEA_Key_256(BYTE* K, WORD* RK);
void LEA_Enc(int Nr, WORD* RK, BYTE* P, BYTE* C);
void LEA_Dec(int Nr, WORD* RK, BYTE* D, BYTE* C);

#endif
