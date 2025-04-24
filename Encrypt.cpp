#include "Encrypt.h"
#include "BlockCipher.h"
#include "BlockCipherMode.h"
#include "util.h"

void Encrypt(int OperateModeNum, int BlockCiphernum)
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
	printf("Plaintext      :");printBlock(data, data_len); printf("\n");
	printf("Plaintext len  :");printf("%d", data_len); printf("\n");

	size_t padded_len;
	if (data_len % BLOCK_SIZE == 0) {
		padded_len = data_len;  
	}
	else {
		padded_len = ((data_len / BLOCK_SIZE) + 1) * BLOCK_SIZE;  
	}

	uint8_t* padded_data = (uint8_t*)malloc(padded_len);
	memset(padded_data, 0, padded_len); 
	memcpy(padded_data, data, data_len);


	printf("padded_data    :\n");printBlock(padded_data, padded_len); printf("\n");
	uint8_t* ReturnEncrypttext;
	uint8_t nonce[NONCE_SIZE];  

	switch (OperateModeNum) {
	uint8_t* ciphertext;
	uint8_t previous_block[16];

	case CBC: // Encrypt
		
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-CBC-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				printf("previous_block    :\n"); printBlock(previous_block, 16); printf("\n");

				printf("block    :\n"); printBlock(block, 16); printf("\n");

				uint8_t* encrypted_block = AES_128_Encrypt(Key, block);

				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16);  
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case AES192:
			printf("AES-CBC-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = AES_192_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16); 
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case AES256:
			printf("AES-CBC-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = AES_256_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16);  
				free(encrypted_block);


			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA128:
			printf("ARIA-CBC-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = ARIA_128_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16);  
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA192:
			printf("ARIA-CBC-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = ARIA_192_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16);  
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA256:
			printf("ARIA-CBC-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16); 
			memset(ciphertext, 0, padded_len); 
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = ARIA_256_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16);  
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;;
		case LEA128:
			printf("LEA-CBC-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = LEA_128_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16); 
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case LEA192:
			printf("LEA-CBC-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16); 
			memset(ciphertext, 0, padded_len); 
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = LEA_192_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16);  
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case LEA256:
			printf("LEA-CBC-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(padded_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);  
			for (size_t i = 0; i < data_len; i += 16) {
				uint8_t block[16];
				memcpy(block, &padded_data[i], 16);
				xorBlocks(block, previous_block, block);
				uint8_t* encrypted_block = LEA_256_Encrypt(Key, block);


				memcpy(&ciphertext[i], encrypted_block, 16);
				memcpy(previous_block, encrypted_block, 16);  
				free(encrypted_block);

			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}

		break; 
	case CTR:
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-CTR-128 Encrypt\n");
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case AES192:
			printf("AES-CTR-192 Encrypt\n");
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case AES256:
			printf("AES-CTR-256 Encrypt\n");
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA128:
			printf("ARIA-CTR-128 Encrypt\n");
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA192:
			printf("ARIA-CTR-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len);  
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA256:
			printf("ARIA-CTR-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memcpy(previous_block, IV, 16);  
			memset(ciphertext, 0, padded_len); 
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case LEA128:
			printf("LEA-CTR-128 Encrypt\n");
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case LEA192:
			printf("LEA-CTR-192 Encrypt\n");
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
			free(ciphertext);
			break;
		case LEA256:
			printf("LEA-CTR-256 Encrypt\n");
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
			printf("Encrypttext    :\n"); printBlock(ciphertext, data_len); printf("\n");
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
			printf("AES-ECB-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = AES_128_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case AES192:
			printf("AES-ECB-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = AES_192_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case AES256:
			printf("AES-ECB-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = AES_256_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA128:
			printf("ARIA-ECB-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = ARIA_128_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA192:
			printf("ARIA-ECB-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = ARIA_192_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case ARIA256:
			printf("ARIA-ECB-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = ARIA_256_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case LEA128:
			printf("LEA-ECB-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = LEA_256_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case LEA192:
			printf("LEA-ECB-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = LEA_256_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		case LEA256:
			printf("LEA-ECB-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(ciphertext, 0, data_len);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[BLOCK_SIZE];
				memcpy(block, &padded_data[i], BLOCK_SIZE);
				uint8_t* encrypted_block = LEA_256_Encrypt(Key, block);
				memcpy(&ciphertext[i], encrypted_block, BLOCK_SIZE);
				free(encrypted_block);
			}
			printf("Encrypttext    :\n"); printBlock(ciphertext, padded_len); printf("\n");
			free(ciphertext);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}
		break; 
	case GCM:
		uint8_t H[BLOCK_SIZE];  
		uint8_t nonce[NONCE_SIZE];  
		uint8_t tag[BLOCK_SIZE];  

		switch (BlockCiphernum) {
		case AES128:
			printf("AES-GCM-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE); 
			get_nonce_from_IV(IV, nonce);  
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = AES_128_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case AES192:
			printf("AES-GCM-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);  
			get_nonce_from_IV(IV, nonce);  
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = AES_192_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case AES256:
			printf("AES-GCM-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE); 
			get_nonce_from_IV(IV, nonce);
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = AES_256_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case ARIA128:
			printf("ARIA-GCM-128 Encrypt\n");

			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);  
			get_nonce_from_IV(IV, nonce); 
	
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = ARIA_128_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case ARIA192:
			printf("ARIA-GCM-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);
			get_nonce_from_IV(IV, nonce);  
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = ARIA_192_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case ARIA256:
			printf("ARIA-GCM-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);  
			get_nonce_from_IV(IV, nonce); 
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = ARIA_256_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case LEA128:
			printf("LEA-GCM-128 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);  
			get_nonce_from_IV(IV, nonce);  
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = LEA_128_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case LEA192:
			printf("LEA-GCM-192 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);  
			get_nonce_from_IV(IV, nonce);  
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = LEA_192_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		case LEA256:
			printf("LEA-GCM-256 Encrypt\n");
			ciphertext = (uint8_t*)malloc(data_len);
			memset(H, 0, BLOCK_SIZE);  
			get_nonce_from_IV(IV, nonce);  
			for (size_t i = 0; i < data_len; i += BLOCK_SIZE) {
				uint8_t block[16];
				memcpy(block, &data[i], BLOCK_SIZE);
				uint8_t used_nonce[12];
				memcpy(used_nonce, nonce, 12);
				uint8_t* encrypted_counter = LEA_256_Encrypt(Key, used_nonce);
				xorBlocks(block, encrypted_counter, block);

				memcpy(&ciphertext[i], block, BLOCK_SIZE);

				incrementNonce(nonce);

				uint8_t copyblock[16];
				memcpy(copyblock, &block[i], BLOCK_SIZE);
				updateGHASH(copyblock, H);
			}

			memcpy(tag, H, BLOCK_SIZE);

	
			printf("GCM Ciphertext: "); printBlock(ciphertext, data_len); printf("\n");
			printf("GCM Tag       : "); printBlock(tag, BLOCK_SIZE); printf("\n");

			free(ciphertext);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}
		break; 
	case NONE:
		Byte* ReturnEncrypttext;
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-128 Encrypt\n");
			ReturnEncrypttext = AES_128_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case AES192:
			printf("AES-192 Encrypt\n");
			ReturnEncrypttext = AES_192_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case AES256:
			printf("AES-256 Encrypt\n");
			ReturnEncrypttext = AES_256_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case ARIA128:
			printf("ARIA-128 Encrypt\n");
			ReturnEncrypttext = ARIA_128_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case ARIA192:
			printf("ARIA-192 Encrypt\n");

			ReturnEncrypttext = ARIA_192_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case ARIA256:
			printf("ARIA-256 Encrypt\n");
			printf("key    : "); printBlock(Key, 32); printf("\n");
			printf("padded_data    : "); printBlock(padded_data, data_len); printf("\n");

			ReturnEncrypttext = ARIA_256_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case LEA128:
			printf("LEA-128 Encrypt\n");
			ReturnEncrypttext = LEA_128_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case LEA192:
			printf("LEA-192 Encrypt\n");
			ReturnEncrypttext = LEA_192_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
			break;
		case LEA256:
			printf("LEA-256 Encrypt\n");
			ReturnEncrypttext = LEA_256_Encrypt(Key, padded_data);
			printf("Encrypttext    : "); printBlock(ReturnEncrypttext, data_len); printf("\n");
			free(ReturnEncrypttext);
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