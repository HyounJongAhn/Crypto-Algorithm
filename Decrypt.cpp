#include "Decrypt.h"
#include "BlockCipher.h"
#include "BlockCipherMode.h"
#include "util.h"
void Decrypt(int OperateModeNum, int BlockCiphernum)
{
	uint8_t Key[32];  
	uint8_t IV[BLOCK_SIZE] = { 0 }; 
	uint8_t data[2048]; 
	size_t data_len = 0;

	input_key(Key);
	input_iv(IV);
	input_data(data, &data_len);

	printf("Key            :");printBlock(Key, sizeof(Key)); printf("\n");
	printf("IV             :");printBlock(IV, sizeof(IV)); printf("\n");
	printf("Ciphertext     :");printBlock(data, data_len); printf("\n");
	printf("Ciphertext len :");printf("%d", data_len); printf("\n");


	uint8_t* ciphertext = (uint8_t*)malloc(data_len);
	memset(ciphertext, 0, data_len);  
	memcpy(ciphertext, data, data_len);

	uint8_t* ReturnPlaintext;
	uint8_t nonce[NONCE_SIZE];
	uint8_t* decryptedtext;

	switch (OperateModeNum) {
	case CBC:
		
		uint8_t previous_block[16];
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-CBC-128 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = AES_128_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case AES192:
			printf("AES-CBC-192 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = AES_192_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case AES256:
			printf("AES-CBC-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = AES_256_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case ARIA128:
			printf("ARIA-CBC-128 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = ARIA_128_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case ARIA192:
			printf("ARIA-CBC-192 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = ARIA_192_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case ARIA256:
			printf("ARIA-CBC-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = ARIA_256_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case LEA128:
			printf("LEA-CBC-128 Decrypt\n");
			printf("ARIA-CBC-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = LEA_128_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
			break;
		case LEA192:
			printf("LEA-CBC-192 Decrypt\n");
			printf("ARIA-CBC-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = LEA_192_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
			break;
		case LEA256:
			printf("LEA-CBC-256 Decrypt\n");
			printf("ARIA-CBC-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);

			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &ciphertext[i], 16);

				uint8_t* decrypted_block = LEA_256_Decrypt(Key, block);

				xorBlocks(decrypted_block, previous_block, block);
				memcpy(&decryptedtext[i], block, 16);

				memcpy(previous_block, &ciphertext[i], 16);

				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}

		break; 
	case CTR:
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-CTR-128 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len); 
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = AES_128_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case AES192:
			printf("AES-CTR-192 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = AES_192_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case AES256:
			printf("AES-CTR-256 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = AES_256_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA128:
			printf("ARIA-CTR-128 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len); 
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = ARIA_128_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA192:
			printf("ARIA-CTR-192 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len); 
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = ARIA_192_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA256:
			printf("ARIA-CTR-256 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = ARIA_256_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case LEA128:
			printf("LEA-CTR-128 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = LEA_128_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case LEA192:
			printf("LEA-CTR-192 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, data_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = LEA_192_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case LEA256:
			printf("LEA-CTR-256 Decrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16); 
			memset(ciphertext, 0, data_len); 
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &data[i], 16);
				uint8_t used_IV[16];
				memcpy(used_IV, previous_block, 16);

				uint8_t* encrypted_counter = LEA_256_Encrypt(Key, used_IV);

				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, 16);

				incrementCounter(previous_block);
			}
			printf("Decrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}
		break; 
	case ECB:
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-ECB-128 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = AES_128_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case AES192:
			printf("AES-ECB-192 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = AES_192_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case AES256:
			printf("AES-ECB-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = AES_256_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case ARIA128:
			printf("ARIA-ECB-128 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = ARIA_128_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case ARIA192:
			printf("ARIA-ECB-192 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = ARIA_192_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case ARIA256:
			printf("ARIA-ECB-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = ARIA_256_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case LEA128:
			printf("LEA-ECB-128 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = LEA_128_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case LEA192:
			printf("LEA-ECB-192 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = LEA_192_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		case LEA256:
			printf("LEA-ECB-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(decryptedtext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &ciphertext[i], BLOCK_SIZE);
				uint8_t* decrypted_block = LEA_256_Decrypt(Key, block);
				memcpy(&decryptedtext[i], decrypted_block, BLOCK_SIZE);
				free(decrypted_block);
			}
			printf("Decrypttext    :\n"); printBlock(decryptedtext, data_len); printf("\n");
			free(decryptedtext);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}
		break; 
	case GCM:
		uint8_t H[BLOCK_SIZE];  
		uint8_t nonce[BLOCK_SIZE]; 
		
		uint8_t tag[33];  

		input_tag(tag);

		switch (BlockCiphernum) {
		case AES128:
			printf("AES-GCM-128 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = AES_128_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case AES192:
			printf("AES-GCM-192 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = AES_192_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case AES256:
			printf("AES-GCM-256 Decrypt\n");
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = AES_256_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case ARIA128:
			printf("ARIA-GCM-128 Decrypt\n");
			
			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce); 
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = ARIA_128_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case ARIA192:
			printf("ARIA-GCM-192 Decrypt\n");

			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = ARIA_192_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case ARIA256:
			printf("ARIA-256 Decrypt\n");

			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = ARIA_256_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case LEA128:
			printf("LEA-GCM-128 Decrypt\n");

			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = LEA_128_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case LEA192:
			printf("LEA-GCM-192 Decrypt\n");

			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = LEA_192_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		case LEA256:
			printf("LEA-GCM-256 Decrypt\n");

			decryptedtext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);

				uint8_t* encrypted_counter = LEA_256_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);
				memcpy(&decryptedtext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			if (memcmp(H, tag, BLOCK_SIZE) != 0) {
				printf("GCM Tag Verification Failed!\n");
			}
			else {
				printf("GCM Tag Verified\n");
			}

			printf("GCM Decrypted Text: "); printBlock(decryptedtext, data_len); printf("\n");

			free(decryptedtext);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}
		break; 
	case NONE:
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-128 Decrypt\n");
			ReturnPlaintext = AES_128_Decrypt(Key, ciphertext);
			printf("Decrypttext    :"); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			free(ciphertext);
			break;
		case AES192:
			printf("AES-192 Decrypt\n");
			ReturnPlaintext = AES_192_Decrypt(Key, ciphertext);
			printf("Decrypttext    :"); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			free(ciphertext);
			break;
		case AES256:
			printf("AES-256 Decrypt\n");
			ReturnPlaintext = AES_256_Decrypt(Key, ciphertext);
			printf("Decrypttext    :"); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			free(ciphertext);
			break;
		case ARIA128:
			printf("ARIA-128 Decrypt\n");
			ReturnPlaintext = ARIA_128_Decrypt(Key, ciphertext);
			printf("Decrypttext    :"); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			free(ciphertext);
			break;
		case ARIA192:
			printf("ARIA-192 Decrypt\n");
			ReturnPlaintext = ARIA_192_Decrypt(Key, ciphertext);
			printf("Decrypttext    :"); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			free(ciphertext);
			break;
		case ARIA256:
			printf("ARIA-256 Decrypt\n");
			ReturnPlaintext = ARIA_256_Decrypt(Key, ciphertext);
			printf("Decrypttext    :"); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			free(ciphertext);
			break;
		case LEA128:
			printf("LEA-128 Decrypt\n");
			ReturnPlaintext = LEA_128_Decrypt(Key, ciphertext);
			printf("Decrypttext    : "); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			break;
		case LEA192:
			printf("LEA-192 Decrypt\n");
			ReturnPlaintext = LEA_192_Decrypt(Key, ciphertext);
			printf("Decrypttext    : "); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			break;;
		case LEA256:
			printf("LEA-256 Decrypt\n");
			ReturnPlaintext = LEA_256_Decrypt(Key, ciphertext);
			printf("Decrypttext    : "); printBlock(ReturnPlaintext, data_len); printf("\n");
			free(ReturnPlaintext);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}
		break; 
	default:
		printf("Invalid Mode of Operation Number\n");
		break;
	}
}
