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
	printf("|       3.1. SHA2	- 224, 256, 384, 512, 512/224, 512/256		|\n");
	printf("|       3.2. SHA3	- 224, 256, 384, 512, 512/224, 512/256		|\n");
	printf("|       3.3. LSH	- 224, 256, 384, 512, 512/224, 512/256		|\n");
	printf("|    4. MAC								|\n");
	printf("|       4.1. HMAC							|\n");
	printf("|    5. PBKDF								|\n");
	printf("|    6. Key Exchange							|\n");
	printf("|       6.1. DH								|\n");
	printf("|       6.2. EC-DH							|\n");
	printf("|    7. Digital Singature					|\n");
	printf("|       7.1. RSA-OAEP					|\n");
	printf("|       7.2. RSA-PSS						|\n");
	printf("|       7.3. DSA								|\n");
	printf("|       7.4. EC-DSA						|\n");
	printf("|       7.5. KCDSA							|\n");
	printf("|       7.6. EC-KCDSA							|\n");
	printf("**********************************************************\n");
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
	printf("Input Number : ");
	if (scanf_s("%d", &Hash_Choose_Num) != 1) {
		while (getchar() != '\n');
	}
	return Hash_Choose_Num;
}
int ChooseModeofOperation()
{
	int OperationMode_Choose_Num = 0;
	printf("Choose BlcokCipher Algorithm : \n");
	printf("1. CBC\n");
	printf("2. CTR\n");
	printf("3. ECB\n");
	printf("4. GCM\n");
	printf("5. NONE\n");
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

void Clear() {
	system("pause");
	system("cls");
}

