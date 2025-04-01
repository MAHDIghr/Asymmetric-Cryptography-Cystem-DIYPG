#include "../../../include/phase1.h"
#include "../../../include/rsa_common_header.h"
#include "../../../include/rsa_tools.h"
#include "../../../include/other_base64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

rsaKey_t pubKey = {65537, 3233};  // Example small RSA public key
rsaKey_t privKey = {413, 3233};   // Example small RSA private key

void test_rsa_single_byte() {
    uint8_t input = 42;
    uint8_t encrypted, decrypted;

    rsa_encrypt(&input, 1, &encrypted, &pubKey);
    rsa_decrypt(&encrypted, 1, &decrypted, &privKey);

    printf("Single Byte Test: input=%d, encrypted=%d, decrypted=%d\n", input, encrypted, decrypted);
    assert(input == decrypted);
}

void test_rsa_multiple_bytes() {
    uint8_t input[] = {10, 20, 30, 40, 50};
    uint8_t encrypted[5], decrypted[5];

    rsa_encrypt(input, 5, encrypted, &pubKey);
    rsa_decrypt(encrypted, 5, decrypted, &privKey);

    printf("Multi-Byte Test: ");
    for (int i = 0; i < 5; i++) {
        printf("%d->%d->%d  ", input[i], encrypted[i], decrypted[i]);
        assert(input[i] == decrypted[i]);
    }
    printf("\n");
}

void test_rsa_empty_input() {
    uint8_t input[1] = {};
    uint8_t encrypted[1], decrypted[1];

    rsa_encrypt(input, 0, encrypted, &pubKey);
    rsa_decrypt(encrypted, 0, decrypted, &privKey);

    printf("Empty Input Test Passed.\n");
}

void test_rsa_max_value() {
    uint8_t input = 255;
    uint8_t encrypted, decrypted;

    rsa_encrypt(&input, 1, &encrypted, &pubKey);
    rsa_decrypt(&encrypted, 1, &decrypted, &privKey);

    printf("Max Byte Value Test: input=%d, encrypted=%d, decrypted=%d\n", input, encrypted, decrypted);
    assert(input == decrypted);
}

int main() {
    test_rsa_single_byte();
    test_rsa_multiple_bytes();
    test_rsa_empty_input();
    test_rsa_max_value();

    printf("\n✅ All RSA unit tests passed successfully!\n");
    return 0;
}