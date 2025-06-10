#include "BlockCipherMode.h"
#include "util.h"


// GCM ����
#define SHIFTR( R, n )                              \
    (R)[3] = ((R)[3] >> n) ^ ((R)[2] << (32 - n)),  \
    (R)[2] = ((R)[2] >> n) ^ ((R)[1] << (32 - n)),  \
    (R)[1] = ((R)[1] >> n) ^ ((R)[0] << (32 - n)),  \
    (R)[0] = ((R)[0] >> n)

#define XOR128( R, A, B )       \
    (R)[0] = (A)[0] ^ (B)[0],   \
    (R)[1] = (A)[1] ^ (B)[1],   \
    (R)[2] = (A)[2] ^ (B)[2],   \
    (R)[3] = (A)[3] ^ (B)[3]

#define INCREASE( ctr )	((ctr)[3] == 0xFFFFFFFF) ? ((ctr)[2]++, (ctr)[3] = 0) : ((ctr)[3]++);
#define ZERO128(a)    a[0] = 0x00000000, a[1] = 0x00000000, a[2] = 0x00000000, a[3] = 0x00000000;

void xorBlocks(uint8_t* block1, uint8_t* block2, uint8_t* result) {
    for (int i = 0; i < 16; i++) {
        result[i] = block1[i] ^ block2[i];
    }
}

void Byte2Word(unsigned int* dst, const uint8_t* src, const int srcLen)
{
    int i = 0;
    int remain = 0;

    for (i = 0; i < srcLen; i++)
    {
        remain = i & 3;

        if (remain == 0)
            dst[i >> 2] = ((unsigned int)src[i] << 24);
        else if (remain == 1)
            dst[i >> 2] ^= ((unsigned int)src[i] << 16);
        else if (remain == 2)
            dst[i >> 2] ^= ((unsigned int)src[i] << 8);
        else
            dst[i >> 2] ^= ((unsigned int)src[i] & 0x000000FF);
    }
}

void Word2Byte(uint8_t* dst, const unsigned int* src, const int srcLen)
{
    int i = 0;
    int remain = 0;

    for (i = 0; i < srcLen; i++)
    {
        remain = i & 3;

        if (remain == 0)
            dst[i] = (unsigned char)(src[i >> 2] >> 24);
        else if (remain == 1)
            dst[i] = (unsigned char)(src[i >> 2] >> 16);
        else if (remain == 2)
            dst[i] = (unsigned char)(src[i >> 2] >> 8);
        else
            dst[i] = (unsigned char)src[i >> 2];
    }
}

void makeM8(unsigned int M[][4], const unsigned int* H)
{
    unsigned int i = 64, j = 0, temp[4] = { 0, };

    M[128][0] = H[0];
    M[128][1] = H[1];
    M[128][2] = H[2];
    M[128][3] = H[3];

    while (i > 0)
    {
        temp[0] = M[i << 1][0];
        temp[1] = M[i << 1][1];
        temp[2] = M[i << 1][2];
        temp[3] = M[i << 1][3];

        if (temp[3] & 0x01)
        {
            SHIFTR(temp, 1);
            temp[0] ^= 0xE1000000;
        }
        else
        {
            SHIFTR(temp, 1);
        }

        M[i][0] = temp[0];
        M[i][1] = temp[1];
        M[i][2] = temp[2];
        M[i][3] = temp[3];

        i >>= 1;
    }

    i = 2;

    while (i < 256)
    {
        for (j = 1; j < i; j++)
        {
            M[i + j][0] = M[i][0] ^ M[j][0];
            M[i + j][1] = M[i][1] ^ M[j][1];
            M[i + j][2] = M[i][2] ^ M[j][2];
            M[i + j][3] = M[i][3] ^ M[j][3];
        }

        i <<= 1;
    }

    M[0][0] = 0;
    M[0][1] = 0;
    M[0][2] = 0;
    M[0][3] = 0;
}

void GHASH_8BIT(unsigned int* out, unsigned int* in, unsigned int M[][4], const unsigned int* R)
{
    unsigned int W[4] = { 0, }, Z[4] = { 0, };
    unsigned int temp = 0, i = 0;

    XOR128(Z, out, in);

    for (i = 0; i < 15; i++)
    {
        temp = ((Z[3 - (i >> 2)] >> ((i & 3) << 3)) & 0xFF);

        W[0] ^= M[temp][0];
        W[1] ^= M[temp][1];
        W[2] ^= M[temp][2];
        W[3] ^= M[temp][3];

        temp = W[3] & 0xFF;

        SHIFTR(W, 8);
        W[0] ^= R[temp];
    }

    temp = (Z[0] >> 24) & 0xFF;

    out[0] = W[0] ^ M[temp][0];
    out[1] = W[1] ^ M[temp][1];
    out[2] = W[2] ^ M[temp][2];
    out[3] = W[3] ^ M[temp][3];
}

void get_nonce_from_IV(uint8_t* iv, uint8_t* nonce) {
    memcpy(nonce, iv, NONCE_SIZE);
}


// CTR ��忡�� ī���� ���� �Լ�
void incrementCounter(uint8_t* counter) {
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) break; 
    }
}
// �±� �Է� �ޱ� (�ִ� 96��Ʈ, 16������ �Է�)
void input_aad(uint8_t* aad, size_t* aad_len) {
    printf("aad�� �Է��ϼ��� �ִ� 256����Ʈ(�Է��� �� �ϰų�, ������ �� 0x00���� ä����):\n");

    char data_input[257];
    *aad_len = 0;

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

        if (*aad_len + len / 2 > 2048 * 1024) {
            break;  // �ִ� ũ�� �ʰ� �� ����
        }

        // ���� ����
        remove_spaces(data_input);
        len = strlen(data_input);  // ���� ���� �� ���� ������

        // 16������ ��ȯ�Ͽ� uint8_t �迭�� ����
        for (size_t i = 0; i < len; i += 2) {
            sscanf(&data_input[i], "%2hhx", &aad[*aad_len + i / 2]);
        }

        // ������ ���� ������Ʈ
        *aad_len += len / 2;
    }

    printf("Data length: %zu bytes\n", *aad_len);
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
    printf("aad�� �Է��ϼ��� �ִ� 128����Ʈ(�Է��� �� �ϰų�, ������ �� 0x00���� ä����):\n");

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