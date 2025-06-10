#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <string>


#ifndef UTIL_H
#define UTIL_H

void print_hex(uint8_t* data, uint8_t len); // 16���� ���
void Information(); // ���α׷� ���� ǥ��
void Informatin_Detail(); // ���α׷� ���� ���� ǥ��

int ChooseBlockCipherAlgorithm(); // ��� ��ȣ �˰��� ����
int ChooseModeofOperation(); // ���� ��� ����
int ChooseHashAlgorithm(); // �ؽ� �˰��� ����
int ChooseHMacAlgorithm(); // HMAC �˰��� ����
int ChoosePBKDFAlgorithm();
// PBKDF �˰��� ����
int ChooseRNGAlgorithm(); // ���� ������ �˰��� ����
void clear_input_buffer();
void remove_spaces(char* str);
int ChooseDigitalSignatureAlgorithm();
void Clear(); // ȭ�� �ʱ�ȭ �Լ�
void ask_input_file(char* path);
void ask_output_file(char* path);
size_t read_chunk(FILE* fin, uint8_t* buffer, size_t size);

// ���� ���� �Լ�
void write_chunk(FILE* fout, uint8_t* buffer, size_t size);
#endif /* UTIL_H */
