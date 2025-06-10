#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <string>


#ifndef UTIL_H
#define UTIL_H

void print_hex(uint8_t* data, uint8_t len); // 16진수 출력
void Information(); // 프로그램 정보 표시
void Informatin_Detail(); // 프로그램 세부 정보 표시

int ChooseBlockCipherAlgorithm(); // 블록 암호 알고리즘 선택
int ChooseModeofOperation(); // 동작 모드 선택
int ChooseHashAlgorithm(); // 해시 알고리즘 선택
int ChooseHMacAlgorithm(); // HMAC 알고리즘 선택
int ChoosePBKDFAlgorithm();
// PBKDF 알고리즘 선택
int ChooseRNGAlgorithm(); // 난수 생성기 알고리즘 선택
void clear_input_buffer();
void remove_spaces(char* str);
int ChooseDigitalSignatureAlgorithm();
void Clear(); // 화면 초기화 함수
void ask_input_file(char* path);
void ask_output_file(char* path);
size_t read_chunk(FILE* fin, uint8_t* buffer, size_t size);

// 파일 쓰기 함수
void write_chunk(FILE* fout, uint8_t* buffer, size_t size);
#endif /* UTIL_H */
