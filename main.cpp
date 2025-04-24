#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <ctype.h>
#include "Encrypt.h"
#include "Decrypt.h"
#include "util.h"
#include "ARIA.h"
#include "Hash.h"
#include "BlockCipher.h"
#define _CRT_SECURE_NO_WARNINGS
//// 알고리즘 불러오기

////

#define ENCRYPT 1
#define DECRYPT 2
#define RNG 3
#define HASH	4
#define MAC 5
#define PBKDF 6
#define KEY_EXCHANGE 7
#define DIGITAL_SIGNATURE 8
#define LIST_OF_CIPHER 9


/*
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

*/
#define HASH_SIZE 32
#define BLOCK_SIZE 64


int main() {
	while (1) {
		int Choose_Num = 0;
		int Hash_Choose_Num = 0;
		int BlockCipher_Choose_Num = 0;
		int OperationMode_Choose_Num = 0;
		Information();
		printf("Input Number : ");
		if (scanf_s("%d", &Choose_Num) != 1) {
			while (getchar() != '\n');
			break;
		}

		switch (Choose_Num)
		{
		case(ENCRYPT):
			printf("Encrypt\n");
			OperationMode_Choose_Num = ChooseModeofOperation();
			BlockCipher_Choose_Num = ChooseBlockCipherAlgorithm();
			while (getchar() != '\n');
			Encrypt(OperationMode_Choose_Num+10, BlockCipher_Choose_Num);
			Clear();
			break;
		case(DECRYPT):
			printf("Decrypt\n");
			OperationMode_Choose_Num = ChooseModeofOperation();
			BlockCipher_Choose_Num = ChooseBlockCipherAlgorithm();
			while (getchar() != '\n');
			Decrypt(OperationMode_Choose_Num+10, BlockCipher_Choose_Num);
			Clear();
			break;
		case(RNG):
			printf("RNG\n");
			Clear();
			break;
		case(HASH):
			printf("Hash\n");
			Hash_Choose_Num = ChooseHashAlgorithm();
			DoHash((int)Hash_Choose_Num);
			Clear();
			break;
		case(MAC):
			printf("MAC\n");
			Clear();
			break;
		case(PBKDF):
			printf("PBKDF\n");
			Clear();
			break;
		case(KEY_EXCHANGE):
			printf("Key Exchange\n");
			Clear();
			break;
		case(DIGITAL_SIGNATURE):
			printf("Digital Signature\n");
			Clear();
			break;
		case(LIST_OF_CIPHER):
			printf("List of Supported Ciphers\n");
			Informatin_Detail();
			Clear();
			break;
		default:
			return 0;
		}
	}
}