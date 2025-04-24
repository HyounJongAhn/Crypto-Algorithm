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
int ChooseHashAlgorithm(); // �ؽ� �˰��� ����
int ChooseBlockCipherAlgorithm(); // ��� ��ȣ �˰��� ����
int ChooseModeofOperation(); // ���� ��� ����
void clear_input_buffer();
void remove_spaces(char* str);

void Clear(); // ȭ�� �ʱ�ȭ �Լ�


#endif /* UTIL_H */
