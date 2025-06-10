#define _CRT_SECURE_NO_WARNINGS
#include "util.h"
#include <stdexcept>
void print_hex(uint8_t* data, uint8_t len) {
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", data[i]);
    printf("\n");
}
void Information() {
	printf("**********************************************************\n");
	printf("|               KOOKMIN UNIVERSITY                       |\n");
	printf("|                Crypto Algorithms                       |\n");
	printf("|                                                        |\n");
	printf("|            List of Supported Ciphers                   |\n");
	printf("|          1. Block Cipher(AES, ARIA, LEA)               |\n");
	printf("|          1. Block Cipher(CBC, ECB, CTR, GCM)           |\n");
	printf("**********************************************************\n");

	printf("1. Encrypt\n");
	printf("2. Decrypt\n");
	printf("3. RNG\n");
	printf("4. Hash\n");
	printf("5. MAC\n");
	printf("6. PBKDF\n");
	printf("7. Key Exchange\n");
	printf("8. Digital Signature\n");
	printf("9. List of Supported Ciphers\n");
	printf("Press any other key to exit.\n");
	printf("-------------------------------------------\n");

}

void Informatin_Detail() {
	system("cls");
	printf("*************************************************************************\n");
	printf("|               KOOKMIN UNIVERSITY                                      |\n");
	printf("|                Crypto Algorithms                                      |\n");
	printf("|                                                                       |\n");
	printf("|      Information of Supported Ciphers                                 |\n");
	printf("|    1. Block Cipher(CBC, ECB, CTR, GCM)                                |\n");
	printf("|       1.1. AES	- 128, 192, 256                                 |\n");
	printf("|       1.2. ARIA	- 128, 192, 256                                 |\n");
	printf("|       1.3. LEA	- 128, 192, 256                                 |\n");
	printf("|    2. RNG                                                             |\n");
	printf("|       2.1. CTR-DRBG                                                   |\n");
	printf("|    3. Hash Function                                                   |\n");
	printf("|       3.1. SHA2	- 224, 256, 384, 512				|\n");
	printf("|       3.2. SHA3	- 224, 256, 384, 512 				|\n");
	printf("|       3.3. LSH	- 224, 256, 384, 512				|\n");
	printf("|    4. MAC								|\n");
	printf("|       4.1. HMAC							|\n");
	printf("|    5. PBKDF2								|\n");
	printf("|    6. Key Exchange							|\n");
	printf("|       6.1. DH								|\n");
	printf("|    7. Digital Singature						|\n");
	printf("|       7.1. RSA-OAEP							|\n");
	printf("|       7.2. RSA-PSS							|\n");
	printf("|       7.3. EC-KCDSA							|\n");
	printf("*************************************************************************\n");
}

int ChooseModeofOperation()
{
	int OperationMode_Choose_Num = 0;
	printf("Choose BlcokCipher Algorithm : \n");
	printf("1. CBC\n");
	printf("2. CTR\n");
	printf("3. ECB\n");
	printf("4. GCM\n");
	printf("Input Number : ");
	if (scanf_s("%d", &OperationMode_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return OperationMode_Choose_Num;
}

int ChooseBlockCipherAlgorithm()
{
	int BlockCipher_Choose_Num = 0;
	printf("Choose BlcokCipher Algorithm : \n");
	printf("1. AES128\n");
	printf("2. AES192\n");
	printf("3. AES256\n");
	printf("4. ARIA128\n");
	printf("5. ARIA192\n");
	printf("6. ARIA256\n");
	printf("7. LEA128\n");
	printf("8. LEA192\n");
	printf("9. LEA256\n");
	printf("Input Number : ");
	if (scanf_s("%d", &BlockCipher_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return BlockCipher_Choose_Num;
}

int ChooseHashAlgorithm()
{
	int Hash_Choose_Num = 0;
	printf("Choose Hash Algorithm : \n");
	printf("1. SHA224\n");
	printf("2. SHA256\n");
	printf("3. SHA384\n");
	printf("4. SHA512\n");
	printf("5. LSH256\n");
	printf("6. LSH512\n");
	printf("7. SHA3-224\n");
	printf("8. SHA3-256\n");
	printf("9. SHA3-384\n");
	printf("10. SHA3-512\n");
	printf("Input Number : ");
	if (scanf_s("%d", &Hash_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return Hash_Choose_Num;
}

int ChooseHMacAlgorithm()
{
	int HMac_Choose_Num = 0;
	printf("Choose Hash Algorithm : \n");
	printf("1. SHA224\n");
	printf("2. SHA256\n");
	printf("3. SHA384\n");
	printf("4. SHA512\n");
	printf("Input Number : ");
	if (scanf_s("%d", &HMac_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return HMac_Choose_Num;
}

int ChoosePBKDFAlgorithm()
{
	int pbkdf_Choose_Num = 0;
	printf("Choose PBKDF Algorithm : \n");
	printf("1. SHA224\n");
	printf("2. SHA256\n");
	printf("3. SHA384\n");
	printf("4. SHA512\n");
	printf("Input Number : ");
	if (scanf_s("%d", &pbkdf_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return pbkdf_Choose_Num;
}

int ChooseRNGAlgorithm() {
	int rng_Choose_Num = 0;
	printf("Choose RNG Algorithm : \n");
	printf("1. CTR-DRBG\n");
	printf("Input Number : ");
	if (scanf_s("%d", &rng_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return rng_Choose_Num;
}

int ChooseDigitalSignatureAlgorithm() {
	int SIgnature_Choose_Num = 0;
	printf("Choose RNG Algorithm : \n");
	printf("1. RSA-PSS\n");
	printf("2. RSA-OAEP\n");
	printf("3. ECKCDSA\n");
	printf("4. RSA GEN KEY\n");
	printf("Input Number : ");
	if (scanf_s("%d", &SIgnature_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return SIgnature_Choose_Num;
}
void clear_input_buffer() {
	while (getchar() != '\n');
}


void remove_spaces(char* str) {
	char* src = str, * dst = str;
	while (*src) {
		if (*src != ' ' && *src != '\n') {
			*dst++ = *src;
		}
		src++;
	}
	*dst = '\0';
}

#define MAX_PATH 256

/* 안전하게 경로 입력받기 & 유효성 검사  ------------------------------ */
void ask_input_file(char* path)
{
	FILE* fp = NULL;

	while (1) {
		printf("Input file path  : ");
		if (!fgets(path, MAX_PATH, stdin))          /* 입력 실패 방지 */
			continue;

		path[strcspn(path, "\n")] = 0;              /* 개행 제거 */

		fp = fopen(path, "rb");
		if (fp == NULL) {
			fprintf(stderr,
				"다시 입력하세요.\n",
				path);
		}
		else {
			fclose(fp);                             /* 열기 성공 → 루프 종료 */
			break;
		}
	}
}

void ask_output_file(char* path)
{
	FILE* fp = NULL;

	while (1) {
		printf("Output file path : ");
		if (!fgets(path, MAX_PATH, stdin))
			continue;

		path[strcspn(path, "\n")] = 0;

		/* 덮어쓰기를 원치 않으면 존재 여부를 확인해서 경고 */
		if ((fp = fopen(path, "rb")) != NULL) {
			fclose(fp);
			printf("[경고] 이미 파일이 존재합니다. 덮어쓰시겠습니까? (y/n): ");
			int ch = getchar();
			while (getchar() != '\n');              /* 잔여 입력 제거 */
			if (ch == 'y' || ch == 'Y') {
				break;                              /* 덮어쓰기 진행 */
			}
			else {
				continue;                           /* 새 경로 재입력 */
			}
		}
		else {
			/* 쓰기 테스트: 경로 및 권한 문제 확인 */
			fp = fopen(path, "wb");
			if (fp == NULL) {
				fprintf(stderr,
					"다시 입력하세요.\n",
					path);
			}
			else {
				fclose(fp);                         /* 쓰기 가능 → 루프 종료 */
				/* 빈 파일 지워 두려면 remove(path); */
				break;
			}
		}
	}
}
size_t read_chunk(FILE* fin, uint8_t* buffer, size_t size) {
	if (fin == NULL || buffer == NULL) {
		fprintf(stderr, "파일 포인터 또는 버퍼가 NULL입니다.\n");
		return 0;
	}
	return fread(buffer, 1, size, fin);
}

// 파일 쓰기 함수
void write_chunk(FILE* fout, uint8_t* buffer, size_t size) {
	fwrite(buffer, 1, size, fout);
}

void Clear() {
	system("pause");
	system("cls");
}

