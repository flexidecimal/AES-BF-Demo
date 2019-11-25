#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "aes.h"

static void phex(uint8_t* str, uint8_t len);
static int test_encrypt_cbc(uint8_t* key, uint8_t* in, uint8_t* out, uint8_t len);
static int test_decrypt_cbc(uint8_t* key, uint8_t* in, uint8_t* out, uint8_t len);

int main(void)
{
    int exit = 1;

    printf("\nTesting AES128\n\n");

    uint8_t key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff };

    uint8_t in[]  = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };

    uint8_t* encrypted = malloc(sizeof(in));
    
    printf("Key: ");
    phex(key, 16);

    printf("Plain Text: ");
    phex(in, sizeof(in));

    test_encrypt_cbc(key, in, encrypted, sizeof(in));

    printf("Cipher Text: ");
    phex(encrypted, sizeof(in));
    printf("\n\n");

    clock_t t;
    t = clock();

    for(int i = 0; i < 256; i++){
        key[15] = i;

        uint8_t* decrypted = malloc(sizeof(in));
        test_decrypt_cbc(key, encrypted, decrypted, sizeof(in));
 
        if(memcmp(in, decrypted, sizeof(in)) == 0){
            printf("Attempt: %d\n", i);
            printf("Key: ");
            phex(key, 16);
            printf("Decrypt: ");
            phex(decrypted, 64);
            printf("PASS\n");
            break; 
        }
    }

    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;

    printf("Brute force took: %f seconds\n\n", time_taken);
    
    return exit;
}

// prints string as hex
static void phex(uint8_t* str, uint8_t len)
{
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static int test_decrypt_cbc(uint8_t* key, uint8_t* in, uint8_t* out, uint8_t len)
{
    memcpy(out, in, len);

    struct AES_ctx ctx;

    uint8_t iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, out, 64);

    return 1;

}

static int test_encrypt_cbc(uint8_t* key, uint8_t* in, uint8_t* out, uint8_t len)
{ 
    printf("Encrypting Packet to brute force!\n");
    memcpy(out, in, len);

    struct AES_ctx ctx;

    uint8_t iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, out, 64);

    return 1; 
}


