#include "BlockCipherMode.h"
#include "util.h"

// ��� XOR �Լ� CTR,GCM
void xorBlocks(uint8_t* block1, uint8_t* block2, uint8_t* result) {
    for (int i = 0; i < 16; i++) {
        result[i] = block1[i] ^ block2[i];
    }
}

// nonce ���� �Լ�
void get_nonce_from_IV(uint8_t* iv, uint8_t* nonce) {
    memcpy(nonce, iv, NONCE_SIZE);
}

// CTR ��忡�� ī���� ���� �Լ�
void incrementCounter(uint8_t* counter) {
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) break; 
    }
}

// GCM ��忡�� ī���� ���� �Լ�
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

// GHASH �Լ� ��� 
void GHASH(uint8_t* input, size_t length, uint8_t* H, uint8_t* result) {
    uint8_t block[BLOCK_SIZE] = { 0 };  

 
    for (size_t i = 0; i < length / BLOCK_SIZE; i++) {
        memcpy(block, &input[i * BLOCK_SIZE], BLOCK_SIZE);  


        xorBlocks(block, H, block);
        memcpy(H, block, BLOCK_SIZE);  
    }

    memcpy(result, H, BLOCK_SIZE);
}

// �±� �Է� �ޱ� (�ִ� 96��Ʈ, 16������ �Է�)
void input_tag(uint8_t* tag) {
    printf("�±׸� �Է��ϼ��� �ִ� 16����Ʈ(�Է��� �� �ϰų�, ������ �� 0x00���� ä����) :\n");

    char tag_input[33];  
    fgets(tag_input, sizeof(tag_input), stdin);
    clear_input_buffer();  

    // ���� ����
    remove_spaces(tag_input);

    size_t key_len = strlen(tag_input);

    // Ű�� ������ 0x00���� ä���
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        if (i < key_len / 2) {
            sscanf_s(&tag_input[i * 2], "%2hhx", &tag[i]);  // 2���ھ� 16������ �о� Key�� ����
        }
        else {
            tag[i] = 0x00;  // Ű�� ª���� ������ 0x00���� ä��
        }
    }
}

// Ű �Է� �ޱ� (�ִ� 256��Ʈ, 16������ �Է�)
void input_key(uint8_t* Key) {
    printf("Ű�� �Է��ϼ��� �ִ� 32����Ʈ(�Է��� �� �ϰų�, ������ �� 0x00���� ä����):\n");

    char key_input[65];  
    fgets(key_input, sizeof(key_input), stdin);
    clear_input_buffer(); 

    // ���� ����
    remove_spaces(key_input);

    size_t key_len = strlen(key_input);

    // Ű�� ������ 0x00���� ä���
    for (size_t i = 0; i < 32; i++) {
        if (i < key_len / 2) {
            sscanf_s(&key_input[i * 2], "%2hhx", &Key[i]);  // 2���ھ� 16������ �о� Key�� ����
        }
        else {
            Key[i] = 0x00;  // Ű�� ª���� ������ 0x00���� ä��
        }
    }
}

// ������ �Է� �ޱ� (�ִ� 2048KB���� ó�� ����)
void input_data(uint8_t* data, size_t* data_len) {
    printf("�����͸� �Է��ϼ��� �ִ� 128����Ʈ(�Է��� �� �ϰų�, ������ �� 0x00���� ä����):\n");

    char data_input[257];
    *data_len = 0;

    while (1) {
        // �� �� �Է� �ޱ�
        if (fgets(data_input, sizeof(data_input), stdin) == NULL) {
            break;  // EOF�� ������ �߻��ϸ� ����
        }

        size_t len = strlen(data_input);

        // �� ���� '\n'�� ����
        if (data_input[len - 1] == '\n') {
            data_input[len - 1] = '\0';
            len--;  // '\n'�� ������ �� ���� ����
        }

        // �� ���� �ԷµǸ� ����
        if (len == 0) {
            break;
        }

        if (*data_len + len / 2 > 2048 * 1024) {
            break;  // �ִ� ũ�� �ʰ� �� ����
        }

        // ���� ����
        remove_spaces(data_input);
        len = strlen(data_input);  // ���� ���� �� ���� ������

        // 16������ ��ȯ�Ͽ� uint8_t �迭�� ����
        for (size_t i = 0; i < len; i += 2) {
            sscanf(&data_input[i], "%2hhx", &data[*data_len + i / 2]);
        }

        // ������ ���� ������Ʈ
        *data_len += len / 2;
    }

    printf("Data length: %zu bytes\n", *data_len);
}


// IV �Է� �ޱ� (�ִ� 16����Ʈ, 16������ �Է�)
void input_iv(uint8_t* iv) {
    printf("IV�� �Է��ϼ��� �ִ� 16����Ʈ(�Է��� �� �ϰų�, ������ �� 0x00���� ä����):\n");

    char iv_input[33];  
    fgets(iv_input, sizeof(iv_input), stdin);
    clear_input_buffer(); 

    // ���� ����
    remove_spaces(iv_input);

    size_t iv_len = strlen(iv_input);

    // IV�� ������ 0x00���� ä���
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        if (i < iv_len / 2) {
            sscanf_s(&iv_input[i * 2], "%2hhx", &iv[i]);  // 2���ھ� 16������ �о� IV�� ����
        }
        else {
            iv[i] = 0x00;  // IV�� ª���� ������ 0x00���� ä��
        }
    }
}