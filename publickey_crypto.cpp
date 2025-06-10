#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "publickey_crypto.h"
#include "KCDSA.h"
int dummy_rng(void* unused) {
    (void)unused;
    return rand();  // 주의: 실제 환경에서는 CSPRNG로 교체 필요
}



int rsa_genkey() {
    rsa_context ctx;
    int nbits = 1024;
    int exponent = 65537;

    CTR_DRBG_CTX drbg;
    uint8_t entropy[48] = { 0x00, };
    for (int i = 0; i < 48; i++) entropy[i] = rand() & 0xFF;
    ctr_drbg_instantiate(&drbg, entropy, 48, NULL, 0);

    rsa_init(&ctx, RSA_PKCS_V15, 0, CTR_DRBG_RNG, &drbg);

    printf("[*] Generating %d-bit RSA key...\n", nbits);
    if (rsa_gen_key(&ctx, nbits, exponent) != 0) {
        printf("[-] Key generation failed.\n");
        return 1;
    }

    printf("[+] Key generated!\n");

    printf("[+] N (modulus):\n");
    mpi_write_file((char*)"  ", &ctx.N, 16, stdout);  // 16진수 출력
    printf("\n[+] E (public exponent):\n");
    mpi_write_file((char*)"  ", &ctx.E, 10, stdout);
    printf("\n[+] D (private exponent):\n");
    mpi_write_file((char*)"  ", &ctx.D, 16, stdout);

    rsa_free(&ctx);
    ctr_drbg_clear(&drbg);
    return 0;
}



void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int rsa_pss()
{
    srand((unsigned)time(NULL));

    CTR_DRBG_CTX drbg;
    uint8_t entropy[48] = { 0x00, };
    for (int i = 0; i < 48; i++) entropy[i] = rand() & 0xFF;
    ctr_drbg_instantiate(&drbg, entropy, 48, NULL, 0);

    rsa_context rsa;
    rsa_init(&rsa, RSA_PKCS_V15, 0, CTR_DRBG_RNG, &drbg);

    // 키 생성 (2048비트, 공개지수 65537)
    printf("Generating RSA key pair...\n");
    if (rsa_gen_key(&rsa, 2048, 65537) != 0) {
        printf("RSA key generation failed.\n");
        return 1;
    }
    printf("RSA key generated.\n");

    printf("[+] Key generated!\n");

    printf("[+] N (modulus):\n");
    mpi_write_file((char*)"  ", &rsa.N, 16, stdout);  // 16진수 출력
    printf("\n[+] E (public exponent):\n");
    mpi_write_file((char*)"  ", &rsa.E, 10, stdout);
    printf("\n[+] D (private exponent):\n");
    mpi_write_file((char*)"  ", &rsa.D, 16, stdout);
    printf("\n[+] P (private exponent):\n");
    mpi_write_file((char*)"  ", &rsa.P, 16, stdout);
    printf("\n[+] Q (private exponent):\n");
    mpi_write_file((char*)"  ", &rsa.Q, 16, stdout);

    char message[1024];
    getchar();
    printf("Enter the message for RSA-PSS: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = 0;

    size_t message_len = strlen(message);

    printf("Message: %s\n", message);
    printf("Message Length: %zu\n", message_len);

    uint8_t signature[256];
    size_t signature_len = sizeof(signature);

    if (rsa_pss_sign(&rsa, (const uint8_t*)message, message_len, signature, &signature_len) == 0) {
        printf("PSS signing success.\n");
        print_hex("Signature", signature, signature_len);
    }
    else {
        printf("PSS signing failed.\n");
        return 1;
    }

    if (rsa_pss_verify(&rsa, (const uint8_t*)message, message_len, signature, signature_len) == 0) {
        printf("PSS signature verification success.\n");
    }
    else {
        printf("PSS signature verification failed.\n");
        print_hex("Signature", signature, signature_len);
        return 1;
    }
    ctr_drbg_clear(&drbg);
    return 0;
}

int rsa_oaep()
{
    srand((unsigned)time(NULL));

    CTR_DRBG_CTX drbg;
    uint8_t entropy[48] = { 0x00, };
    for (int i = 0; i < 48; i++) entropy[i] = rand() & 0xFF;
    ctr_drbg_instantiate(&drbg, entropy, 48, NULL, 0);

    rsa_context rsa;
    rsa_init(&rsa, RSA_PKCS_V15, 0, CTR_DRBG_RNG, &drbg);

    // 키 생성 (2048비트, 공개지수 65537)
    printf("Generating RSA key pair...\n");
    if (rsa_gen_key(&rsa, 2048, 65537) != 0) {
        printf("RSA key generation failed.\n");
        return 1;
    }
    printf("RSA key generated.\n");

    printf("[+] Key generated!\n");

    printf("[+] N (modulus):\n");
    mpi_write_file((char*)"  ", &rsa.N, 16, stdout);  // 16진수 출력
    printf("\n[+] E (public exponent):\n");
    mpi_write_file((char*)"  ", &rsa.E, 10, stdout);
    printf("\n[+] D (private exponent):\n");
    mpi_write_file((char*)"  ", &rsa.D, 16, stdout);
    printf("\n[+] P (private exponent):\n");
    mpi_write_file((char*)"  ", &rsa.P, 16, stdout);
    printf("\n[+] Q (private exponent):\n");
    mpi_write_file((char*)"  ", &rsa.Q, 16, stdout);

    char message[1024];
    getchar();
    // Prompt the user to input a message
    printf("Enter the message for RSA-PSS: ");
    fgets(message, sizeof(message), stdin);  // Get input from the user
    message[strcspn(message, "\n")] = 0;  // Remove the newline character if present

    // Calculate the length of the message
    size_t message_len = strlen(message);

    // Output the message and its length
    printf("Message: %s\n", message);
    printf("Message Length: %zu\n", message_len);

    // OAEP 암호화 테스트
    uint8_t ciphertext[512];
    size_t ciphertext_len = sizeof(ciphertext);
    uint8_t decrypted[512];
    size_t decrypted_len = sizeof(decrypted);

    if (rsa_oaep_encrypt(&rsa, (const uint8_t*)message, message_len, ciphertext, &ciphertext_len) == 0) {
        printf("OAEP encryption success.\n");
        print_hex("Ciphertext", ciphertext, ciphertext_len);
    }
    else {
        printf("OAEP encryption failed.\n");
        return 1;
    }

    if (rsa_oaep_decrypt(&rsa, ciphertext, ciphertext_len, decrypted, &decrypted_len) == 0) {
        printf("OAEP decryption success.\nDecrypted message (%zu bytes): %.*s\n", decrypted_len, (int)decrypted_len, decrypted);
        print_hex("Decrypted (raw bytes)", decrypted, decrypted_len);
    }
    else {
        printf("OAEP decryption failed.\n");
        print_hex("Decrypted (raw bytes)", decrypted, decrypted_len);
    }
    ctr_drbg_clear(&drbg);
    return 0;
}

int DoSignature(int num) {
    switch (num) {
    case 1:
        rsa_pss();
        break;
    case 2:
        rsa_oaep();
        break;
    case 3:
        KCDSA();
        break;
    case 4:
        rsa_genkey();
        break;
    }
    return 0;
}