#include "BlockCipherMode.h"
#include "util.h"

// 블록 XOR 함수 CTR,GCM
void xorBlocks(uint8_t* block1, uint8_t* block2, uint8_t* result) {
    for (int i = 0; i < 16; i++) {
        result[i] = block1[i] ^ block2[i];
    }
}

// nonce 생성 함수
void get_nonce_from_IV(uint8_t* iv, uint8_t* nonce) {
    memcpy(nonce, iv, NONCE_SIZE);
}

// CTR 모드에서 카운터 증가 함수
void incrementCounter(uint8_t* counter) {
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) break; 
    }
}

// GCM 모드에서 카운터 증가 함수
void incrementNonce(uint8_t* counter) {
    for (int i = NONCE_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) break;  
    }
}

void updateGHASH(uint8_t* block, uint8_t* H) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        H[i] ^= block[i];  
    }
}

// GHASH 함수 계산 
void GHASH(uint8_t* input, size_t length, uint8_t* H, uint8_t* result) {
    uint8_t block[BLOCK_SIZE] = { 0 };  

 
    for (size_t i = 0; i < length / BLOCK_SIZE; i++) {
        memcpy(block, &input[i * BLOCK_SIZE], BLOCK_SIZE);  


        xorBlocks(block, H, block);
        memcpy(H, block, BLOCK_SIZE);  
    }

    memcpy(result, H, BLOCK_SIZE);
}

// 태그 입력 받기 (최대 96비트, 16진수로 입력)
void input_tag(uint8_t* tag) {
    printf("태그를 입력하세요 최대 16바이트(입력을 안 하거나, 부족할 시 0x00으로 채워짐) :\n");

    char tag_input[33];  
    fgets(tag_input, sizeof(tag_input), stdin);
    clear_input_buffer();  

    // 공백 제거
    remove_spaces(tag_input);

    size_t key_len = strlen(tag_input);

    // 키가 없으면 0x00으로 채우기
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        if (i < key_len / 2) {
            sscanf_s(&tag_input[i * 2], "%2hhx", &tag[i]);  // 2글자씩 16진수로 읽어 Key에 저장
        }
        else {
            tag[i] = 0x00;  // 키가 짧으면 나머지 0x00으로 채움
        }
    }
}

// 키 입력 받기 (최대 256비트, 16진수로 입력)
void input_key(uint8_t* Key) {
    printf("키를 입력하세요 최대 32바이트(입력을 안 하거나, 부족할 시 0x00으로 채워짐):\n");

    char key_input[65];  
    fgets(key_input, sizeof(key_input), stdin);
    clear_input_buffer(); 

    // 공백 제거
    remove_spaces(key_input);

    size_t key_len = strlen(key_input);

    // 키가 없으면 0x00으로 채우기
    for (size_t i = 0; i < 32; i++) {
        if (i < key_len / 2) {
            sscanf_s(&key_input[i * 2], "%2hhx", &Key[i]);  // 2글자씩 16진수로 읽어 Key에 저장
        }
        else {
            Key[i] = 0x00;  // 키가 짧으면 나머지 0x00으로 채움
        }
    }
}

// 데이터 입력 받기 (최대 2048KB까지 처리 가능)
void input_data(uint8_t* data, size_t* data_len) {
    printf("데이터를 입력하세요 최대 128바이트(입력을 안 하거나, 부족할 시 0x00으로 채워짐):\n");

    char data_input[257];
    *data_len = 0;

    while (1) {
        // 한 줄 입력 받기
        if (fgets(data_input, sizeof(data_input), stdin) == NULL) {
            break;  // EOF나 오류가 발생하면 종료
        }

        size_t len = strlen(data_input);

        // 줄 끝의 '\n'을 제거
        if (data_input[len - 1] == '\n') {
            data_input[len - 1] = '\0';
            len--;  // '\n'을 제거한 후 길이 조정
        }

        // 빈 줄이 입력되면 종료
        if (len == 0) {
            break;
        }

        if (*data_len + len / 2 > 2048 * 1024) {
            break;  // 최대 크기 초과 시 종료
        }

        // 공백 제거
        remove_spaces(data_input);
        len = strlen(data_input);  // 공백 제거 후 길이 재조정

        // 16진수로 변환하여 uint8_t 배열에 저장
        for (size_t i = 0; i < len; i += 2) {
            sscanf(&data_input[i], "%2hhx", &data[*data_len + i / 2]);
        }

        // 데이터 길이 업데이트
        *data_len += len / 2;
    }

    printf("Data length: %zu bytes\n", *data_len);
}


// IV 입력 받기 (최대 16바이트, 16진수로 입력)
void input_iv(uint8_t* iv) {
    printf("IV를 입력하세요 최대 16바이트(입력을 안 하거나, 부족할 시 0x00으로 채워짐):\n");

    char iv_input[33];  
    fgets(iv_input, sizeof(iv_input), stdin);
    clear_input_buffer(); 

    // 공백 제거
    remove_spaces(iv_input);

    size_t iv_len = strlen(iv_input);

    // IV가 없으면 0x00으로 채우기
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        if (i < iv_len / 2) {
            sscanf_s(&iv_input[i * 2], "%2hhx", &iv[i]);  // 2글자씩 16진수로 읽어 IV에 저장
        }
        else {
            iv[i] = 0x00;  // IV가 짧으면 나머지 0x00으로 채움
        }
    }
}