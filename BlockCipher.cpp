#include "BlockCipher.h"

uint8_t* AES_128_Encrypt(uint8_t* key, uint8_t* data)
{
	AES aes;
	AES_init(&aes, key, 16);  
	uint8_t* ct = (uint8_t*)malloc(blockBytesLen);  

	AES_encrypt(&aes, ct, data);  

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, ct, BLOCK_SIZE);
	AES_free(&aes);  // AES 구조체 메모리 해제

	return result;
}

uint8_t* AES_128_Decrypt(uint8_t* key, uint8_t* data)
{
	AES aes;
	AES_init(&aes, key, 16); 
	uint8_t* pt = (uint8_t*)malloc(blockBytesLen);  

	AES_decrypt(&aes, pt, data);  

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, pt, BLOCK_SIZE);
	AES_free(&aes);  // AES 구조체 메모리 해제
	return result;
}
uint8_t* AES_192_Encrypt(uint8_t* key, uint8_t* data)
{
	AES aes;
	AES_init(&aes, key, 24); 
	uint8_t* ct = (uint8_t*)malloc(blockBytesLen);  

	AES_encrypt(&aes, ct, data); 

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, ct, BLOCK_SIZE);
	AES_free(&aes);  // AES 구조체 메모리 해제
	return result;
}

uint8_t* AES_192_Decrypt(uint8_t* key, uint8_t* data)
{
	AES aes;
	AES_init(&aes, key, 24); 
	uint8_t* pt = (uint8_t*)malloc(blockBytesLen); 

	AES_decrypt(&aes, pt, data);  

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, pt, BLOCK_SIZE);
	AES_free(&aes);  // AES 구조체 메모리 해제

	return result;
}

uint8_t* AES_256_Encrypt(uint8_t* key, uint8_t* data)
{
	AES aes;
	AES_init(&aes, key, 32);  
	uint8_t* ct = (uint8_t*)malloc(blockBytesLen); 

	AES_encrypt(&aes, ct, data);  

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, ct, BLOCK_SIZE);
	AES_free(&aes);  // AES 구조체 메모리 해제

	return result;
}

uint8_t* AES_256_Decrypt(uint8_t* key, uint8_t* data)
{
	AES aes;
	AES_init(&aes, key, 32);  
	uint8_t* pt = (uint8_t*)malloc(blockBytesLen);  

	AES_decrypt(&aes, pt, data);  

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, pt, BLOCK_SIZE);
	AES_free(&aes);  // AES 구조체 메모리 해제

	return result;
}


// ARIA	
uint8_t* ARIA_128_Encrypt(uint8_t* key, uint8_t* data)
{
	Byte mk[16];
	memset(mk, 0, sizeof(mk));
	memcpy(mk, key, 16);
	Byte rk[16 * 17];

	Byte *p = data;
	Byte c[BLOCK_SIZE];
	Crypt(p, EncKeySetup(mk, rk, 128), rk, c);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, c, BLOCK_SIZE);
	return result;
}

uint8_t* ARIA_128_Decrypt(uint8_t* key, uint8_t* data)
{
	Byte mk[16];
	memset(mk, 0, sizeof(mk));
	memcpy(mk, key, 16);
	Byte rk[16 * 17];

	Byte *c = data;
	Byte p[BLOCK_SIZE];
	DecKeySetup(mk, rk, 128);
	Crypt(c, 12, rk, p);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, p, BLOCK_SIZE);
	return result;
}

uint8_t* ARIA_192_Encrypt(uint8_t* key, uint8_t* data)
{
	Byte mk[24];
	memset(mk, 0, sizeof(mk));
	memcpy(mk, key, 24);
	Byte rk[16 * 17];

	Byte* p = data;
	Byte c[BLOCK_SIZE];
	Crypt(p, EncKeySetup(mk, rk, 192), rk, c);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, c, BLOCK_SIZE);
	return result;
}

uint8_t* ARIA_192_Decrypt(uint8_t* key, uint8_t* data)
{
	Byte mk[24];
	memset(mk, 0, sizeof(mk));
	memcpy(mk, key, 24);
	Byte rk[16 * 17];

	Byte* c = data;
	Byte p[BLOCK_SIZE];
	DecKeySetup(mk, rk, 192);
	Crypt(c, 14, rk, p);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, p, BLOCK_SIZE);
	return result;
}

uint8_t* ARIA_256_Encrypt(uint8_t* key, uint8_t* data)
{
	Byte mk[32];
	memset(mk, 0, sizeof(mk));
	memcpy(mk, key, 32);
	Byte rk[16 * 17];

	Byte* p = data;
	Byte c[BLOCK_SIZE];
	Crypt(p, EncKeySetup(mk, rk, 256), rk, c);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, c, BLOCK_SIZE);
	return result;
}

uint8_t* ARIA_256_Decrypt(uint8_t* key, uint8_t* data)
{
	Byte mk[32];
	memset(mk, 0, sizeof(mk));
	memcpy(mk, key, 32);
	Byte rk[16 * 17];

	Byte* c = data;
	Byte p[BLOCK_SIZE];

	DecKeySetup(mk, rk, 256);
	Crypt(c, 16, rk, p);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, p, BLOCK_SIZE);
	return result;
}


// LEA
uint8_t* LEA_128_Encrypt(uint8_t* key, uint8_t* data)
{
	WORD pdwRoundKey[384] = { 0x0, };
	LEA_Key_128(key, pdwRoundKey);
	Byte c[BLOCK_SIZE];
	LEA_Enc(24, pdwRoundKey, data, c);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, c, BLOCK_SIZE);
	return result;
}

uint8_t* LEA_128_Decrypt(uint8_t* key, uint8_t* data)
{
	WORD pdwRoundKey[384] = { 0x0, };
	LEA_Key_128(key, pdwRoundKey);
	Byte p[BLOCK_SIZE];
	LEA_Dec(24, pdwRoundKey, p, data);

	
	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, p, BLOCK_SIZE);
	return result;
}

uint8_t* LEA_192_Encrypt(uint8_t* key, uint8_t* data)
{
	WORD pdwRoundKey[384] = { 0x0, };
	LEA_Key_192(key, pdwRoundKey);
	Byte c[BLOCK_SIZE];
	LEA_Enc(28, pdwRoundKey, data,c);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, c, BLOCK_SIZE);
	return result;
}

uint8_t* LEA_192_Decrypt(uint8_t* key, uint8_t* data)
{
	WORD pdwRoundKey[384] = { 0x0, };
	LEA_Key_192(key, pdwRoundKey);
	Byte p[BLOCK_SIZE];
	LEA_Dec(28,pdwRoundKey,p,data);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, p, BLOCK_SIZE);
	return result;
}

uint8_t* LEA_256_Encrypt(uint8_t* key, uint8_t* data)
{
	WORD pdwRoundKey[384] = { 0x0, };
	LEA_Key_256(key, pdwRoundKey);
	Byte c[BLOCK_SIZE];
	LEA_Enc(32, pdwRoundKey, data, c);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, c, BLOCK_SIZE);
	return result;
}

uint8_t* LEA_256_Decrypt(uint8_t* key, uint8_t* data)
{
	WORD pdwRoundKey[384] = { 0x0, };
	LEA_Key_256(key, pdwRoundKey);
	Byte p[BLOCK_SIZE];
	LEA_Dec(32, pdwRoundKey, p, data);

	uint8_t* result = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(result, p, BLOCK_SIZE);
	return result;
}
