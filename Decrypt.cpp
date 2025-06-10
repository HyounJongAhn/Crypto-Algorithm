#define _CRT_SECURE_NO_WARNINGS
#include "Decrypt.h"
#include "BlockCipher.h"
#include "BlockCipherMode.h"
#include "util.h"
#include "AES_GCM.h"

#define BUFFER_SIZE 1024*256 
void Decrypt(int OperateModeNum, int BlockCiphernum)
{
	uint8_t Key[32];  
	uint8_t IV[BLOCK_SIZE] = { 0 }; 
	size_t data_len = 0;
	char in_path[256];
	char out_path[256];

	ask_input_file(in_path);
	ask_output_file(out_path);
	input_key(Key);
	input_iv(IV);


	FILE* fin = fopen(in_path, "rb");   /* ✔︎ binary(read)  */
	FILE* fout = fopen(out_path, "wb");
	printf("Key            :");printBlock(Key, sizeof(Key)); printf("\n");
	printf("IV             :");printBlock(IV, sizeof(IV)); printf("\n");

	fseek(fin, 0, SEEK_END); // 파일 포인터를 파일 끝으로 이동
	long int size = ftell(fin);
	fseek(fin, 0, SEEK_SET);
	uint8_t aad[32];
	size_t add_len = 0;
	unsigned char tag[16] = { 0, };
	size_t total_read = 0;
	size_t bytes_read = 0;
	size_t total_size = size;
	uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
	uint8_t* out_buffer = (uint8_t*)malloc(BUFFER_SIZE);
	size_t last_padding = 0;  // 마지막 블록의 패딩 크기
	uint8_t temp[16];
	uint8_t nonce[16];
	size_t last_block_padding = 0;
	size_t read_len;

	int R;
	switch (OperateModeNum) {
	case CBC:
		AES aes;
		uint8_t inbuf[16], outbuf[16];
		Byte rk[16 * 17];
		uint8_t previous_block[16];
		memcpy(previous_block, IV, 16);
		uint8_t block[16];
		WORD pdwRoundKey[384];
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-CBC-128 Decrypt\n");
			
			AES_init(&aes, Key, 16);             /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음
					
					memcpy(inbuf, buffer + i, read_len);

					AES_decrypt(&aes, outbuf, inbuf, 1);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			AES_free(&aes);
			break;
		case AES192:
			printf("AES-CBC-192 Decrypt\n");
			AES_init(&aes, Key, 24);             /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					AES_decrypt(&aes, outbuf, inbuf, 1);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			AES_free(&aes);
			break;
		case AES256:
			printf("AES-CBC-256 Decrypt\n");
			AES_init(&aes, Key, 32);             /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					AES_decrypt(&aes, outbuf, inbuf, 1);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			AES_free(&aes);
			break;
		case ARIA128:
			printf("ARIA-CBC-128 Decrypt\n");

			memset(rk, 0, 16 * 17);
			R = ARIA_128init(Key, 128, rk, 2);             /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					Crypt(inbuf, R, rk, outbuf);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case ARIA192:
			printf("ARIA-CBC-192 Decrypt\n");
			memset(rk, 0, 16 * 17);
			R = ARIA_192init(Key, 192, rk, 2);             /* 키 스케줄 1회 */
			
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					Crypt(inbuf, R, rk, outbuf);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case ARIA256:
			printf("ARIA-CBC-256 Decrypt\n");
			R = ARIA_256init(Key, 256, rk, 2);
			memset(rk, 0, 16*17);
			          /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					Crypt(inbuf, R, rk, outbuf);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA128:
			printf("LEA-CBC-128 Decrypt\n");
			
			memset(pdwRoundKey, 0, 384);
			LEA_Key_128(Key, pdwRoundKey);

         /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					LEA_Dec(24, pdwRoundKey, outbuf, inbuf);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA192:
			printf("LEA-CBC-192 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_128(Key, pdwRoundKey);

			/* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					LEA_Dec(28, pdwRoundKey, outbuf, inbuf);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA256:
			printf("LEA-CBC-256 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_128(Key, pdwRoundKey);

			/* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					LEA_Dec(32, pdwRoundKey, outbuf, inbuf);
					xorBlocks(outbuf, previous_block, block);

					memcpy(previous_block, inbuf, 16);  /* 체이닝 */

					memcpy(out_buffer + i, block, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(block, 1, 16, fout);
			last_block_padding = block[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(block, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(block, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		default:
			printf("Invalid Block Cipher Number\n");
			break;
		}

		break; 
	case CTR:
		read_len = 0;
		switch (BlockCiphernum) {
		case AES128:
			printf("AES-CTR-128 Decrypt\n");
			AES_init(&aes, Key, 16);             /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					AES_encrypt(&aes, outbuf, used_IV, 1);  /* 암호화 */
					xorBlocks(inbuf, outbuf, temp);

					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			AES_free(&aes);
			free(buffer);
			free(out_buffer);
			break;
		case AES192:
			printf("AES-CTR-192 Decrypt\n");
			AES_init(&aes, Key, 24);             /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					AES_encrypt(&aes, outbuf, used_IV, 1);  /* 암호화 */
					xorBlocks(inbuf, outbuf, temp);

					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			AES_free(&aes);
			free(buffer);
			free(out_buffer);
			break;
		case AES256:
			printf("AES-CTR-256 Decrypt\n");
			AES_init(&aes, Key, 32);             /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					AES_encrypt(&aes, outbuf, used_IV, 1);  /* 암호화 */
					xorBlocks(inbuf, outbuf, temp);

					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			AES_free(&aes);
			free(buffer);
			free(out_buffer);
			break;
		case ARIA128:
			printf("ARIA-CTR-128 Decrypt\n");
			memset(rk, 0, 16 * 17);
			R = ARIA_128init(Key, 128, rk, 1);
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					Crypt(used_IV, R, rk, outbuf);  /* 암호화 */
					xorBlocks(inbuf, outbuf, temp);

					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case ARIA192:
			printf("ARIA-CTR-192 Decrypt\n");
			memset(rk, 0, 16 * 17);
			R = ARIA_192init(Key, 192, rk, 1);
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					Crypt(used_IV, R, rk, outbuf);  /* 암호화 */
					xorBlocks(inbuf, outbuf, temp);

					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case ARIA256:
			printf("ARIA-CTR-256 Decrypt\n");
			memset(rk, 0, 16 * 17);
			R = ARIA_256init(Key, 256, rk, 1);
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					Crypt(used_IV, R, rk, outbuf);  /* 암호화 */
					xorBlocks(inbuf, outbuf, temp);

					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA128:
			printf("LEA-CTR-128 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_128(Key, pdwRoundKey);          /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					LEA_Enc(24, pdwRoundKey, used_IV, outbuf);
					xorBlocks(inbuf, outbuf, temp);  /* CBC XOR */


					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA192:
			printf("LEA-CTR-192 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_192(Key, pdwRoundKey);          /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					LEA_Enc(28, pdwRoundKey, used_IV, outbuf);
					xorBlocks(inbuf, outbuf, temp);  /* CBC XOR */


					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA256:
			printf("LEA-CTR-256 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_256(Key, pdwRoundKey);          /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					uint8_t used_IV[16];
					memcpy(used_IV, previous_block, 16);

					LEA_Enc(32, pdwRoundKey, used_IV, outbuf);
					xorBlocks(inbuf, outbuf, temp);  /* CBC XOR */


					incrementCounter(previous_block);
					memcpy(out_buffer + i, temp, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
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
			AES_init(&aes, Key, 16);             /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					AES_decrypt(&aes, outbuf, inbuf, 1);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			AES_free(&aes);
			break;
		case AES192:
			printf("AES-ECB-192 Decrypt\n");
			AES_init(&aes, Key, 24);             /* 키 스케줄 1회 */
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					AES_decrypt(&aes, outbuf, inbuf, 1);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			AES_free(&aes);
			break;
		case AES256:
			printf("AES-ECB-256 Decrypt\n");
			AES_init(&aes, Key, 32);             /* 키 스케줄 1회 */
			size_t read_len;
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					AES_decrypt(&aes, outbuf, inbuf, 1);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			AES_free(&aes);
			break;
		case ARIA128:
			printf("ARIA-ECB-128 Decrypt\n");

			memset(rk, 0, 16 * 17);
			R = ARIA_128init(Key, 128, rk, 2);             /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					Crypt(inbuf, R, rk, outbuf);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case ARIA192:
			printf("ARIA-ECB-192 Decrypt\n");
			memset(rk, 0, 16 * 17);
			R = ARIA_192init(Key, 192, rk, 2);             /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					Crypt(inbuf, R, rk, outbuf);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case ARIA256:
			printf("ARIA-ECB-256 Decrypt\n");
			memset(rk, 0, 16 * 17);
			R = ARIA_256init(Key, 256, rk, 2);             /* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					Crypt(inbuf, R, rk, outbuf);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA128:
			printf("LEA-ECB-128 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_128(Key, pdwRoundKey);

			/* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					LEA_Dec(24, pdwRoundKey, outbuf, inbuf);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA192:
			printf("LEA-ECB-128 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_192(Key, pdwRoundKey);

			/* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					LEA_Dec(28, pdwRoundKey, outbuf, inbuf);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;
		case LEA256:
			printf("LEA-ECB-256 Decrypt\n");
			memset(pdwRoundKey, 0, 384);
			LEA_Key_256(Key, pdwRoundKey);

			/* 키 스케줄 1회 */

			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;  // 남은 데이터를 읽음

					memcpy(inbuf, buffer + i, read_len);

					LEA_Dec(32, pdwRoundKey, outbuf, inbuf);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행
					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;

				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			fseek(fout, -16, SEEK_END);
			fread(outbuf, 1, 16, fout);
			last_block_padding = outbuf[15];  // 마지막 바이트는 패딩 크기
			if (last_block_padding > 0 && last_block_padding < 16) {  // 패딩이 유효한 경우
				// 패딩된 바이트 제외하고 기록
				fwrite(outbuf, 1, 16 - last_block_padding, fout);
			}
			else {
				// 패딩이 없거나, 패딩이 전부일 경우 전체 블록 기록
				fwrite(outbuf, 1, 16, fout);
			}
			fclose(fin);
			fclose(fout);
			free(buffer);
			free(out_buffer);
			break;

		}
	case GCM:
		GCM_CTX params;
		input_tag(tag);
		switch (BlockCiphernum) {
		case AES128:
			input_aad(aad, &add_len);
			get_nonce_from_IV(IV, nonce);
			GCM_Decrypt_init(&params, Key, 16, nonce, 96, aad, add_len);
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					GCM_Decrypt_update(&params, inbuf, 16, outbuf, 16);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			GCM_Decrypt_final(&params, tag, 16);

			fseek(fout, -16, SEEK_END);
			fwrite(outbuf, 1, 16, fout);
			fclose(fin);
			fclose(fout);

			printf("tag\n");
			for (int i = 0; i < 16; i++)
			{
				printf("%02X ", tag[i]);
			}

			free(buffer);
			free(out_buffer);
			break;

		case AES192:
			input_aad(aad, &add_len);
			get_nonce_from_IV(IV, nonce);
			GCM_Decrypt_init(&params, Key, 24, nonce, 96, aad, add_len);
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					GCM_Decrypt_update(&params, inbuf, 16, outbuf, 16);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			GCM_Decrypt_final(&params, tag, 16);

			fseek(fout, -16, SEEK_END);
			fwrite(outbuf, 1, 16, fout);
			fclose(fin);
			fclose(fout);

			printf("tag\n");
			for (int i = 0; i < 16; i++)
			{
				printf("%02X ", tag[i]);
			}

			free(buffer);
			free(out_buffer);
			break;

		case AES256:
			input_aad(aad, &add_len);
			get_nonce_from_IV(IV, nonce);
			GCM_Decrypt_init(&params, Key, 32, nonce, 96, aad, add_len);
			while ((bytes_read = read_chunk(fin, buffer, BUFFER_SIZE)) > 0) {
				size_t i = 0;

				while (i < bytes_read) {
					size_t read_len = (bytes_read - i < 16) ? bytes_read - i : 16;
					memcpy(inbuf, buffer + i, read_len);

					GCM_Decrypt_update(&params, inbuf, 16, outbuf, 16);

					memcpy(out_buffer + i, outbuf, 16);
					i += 16;  // 16바이트씩 진행

					// 진행 상황 출력 (매 1MB마다)
					total_read += 16;
				}
				write_chunk(fout, out_buffer, bytes_read);
			}
			GCM_Decrypt_final(&params, tag, 16);

			fseek(fout, -16, SEEK_END);
			fwrite(outbuf, 1, 16, fout);
			fclose(fin);
			fclose(fout);

			printf("tag\n");
			for (int i = 0; i < 16; i++)
			{
				printf("%02X ", tag[i]);
			}

			free(buffer);
			free(out_buffer);
			break;
		}
	default:
		printf("Invalid Mode of Operation Number\n");
		break;
	}
}
