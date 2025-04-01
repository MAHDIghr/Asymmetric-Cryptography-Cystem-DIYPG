#include "../../../include/phase1.h"
#include "../../../include/rsa_common_header.h"
#include "../../../include/rsa_tools.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void test_rsa_encrypt_decrypt(const uint8_t *input, uint64_t length, const char *test_name) {
    rsaKey_t pubKey, privKey;
    pubKey.E = 3;   // Exposant de la clé publique
    pubKey.N = 257; // Modulo de la clé publique
    privKey.E = 171; // Exposant privé, inverse de 3 mod (257-1)
    privKey.N = 257; // Modulo de la clé privée

    uint8_t encrypted[length];
    uint8_t decrypted[length];

    // Chiffrement
    rsa_encrypt(input, length, encrypted, &pubKey);
    printf("Chiffrement: input[0] = 0x%02x, output[0] = 0x%02x\n", input[0], encrypted[0]);

    // Déchiffrement
    rsa_decrypt(encrypted, length, decrypted, &privKey);
    printf("Déchiffrement: input[0] = 0x%02x, output[0] = 0x%02x\n", encrypted[0], decrypted[0]);

    // Test d'assertion
    for (uint64_t i = 0; i < length; i++) {
        assert(input[i] == decrypted[i]);
    }

    printf("%s succeeded.\n", test_name);
}

void test_rsa_single_byte() {
    uint8_t input[] = { 0x42 };  // Message de 1 octet (ASCII 'B')
    uint64_t length = 1;  // Longueur du message

    printf("Test RSA avec 1 octet (input = 0x42)\n");
    test_rsa_encrypt_decrypt(input, length, "Test 1");
}


void test_rsa_multiple_bytes() {
    uint8_t input[] = { 0x42, 0x43, 0x44, 0x45 };  // Message de 4 octets (ASCII 'B', 'C', 'D', 'E')
    uint64_t length = 4;  // Longueur du message

    printf("Test RSA avec plusieurs octets (input = 0x42 0x43 0x44 0x45)\n");
    test_rsa_encrypt_decrypt(input, length, "Test 2");
}

void test_rsa_empty_message() {
    uint8_t input[] = {};  // Message vide
    uint64_t length = 0;  // Longueur du message

    printf("Test RSA avec message vide\n");
    test_rsa_encrypt_decrypt(input, length, "Test 3");
}


void test_rsa_long_message() {
    uint8_t input[] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C };  // "Hello World" en ASCII
    uint64_t length = 10;  // Longueur du message

    printf("Test RSA avec message long (input = 'Hello World')\n");
    test_rsa_encrypt_decrypt(input, length, "Test 4");
}


void test_rsa_8_bytes_message() {
    uint8_t input[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };  // Message de 8 octets
    uint64_t length = 8;  // Longueur du message

    printf("Test RSA avec 8 octets (input = 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08)\n");
    test_rsa_encrypt_decrypt(input, length, "Test 5");
}

//############################################################# BASE 64 ##############################################################################

void test_base64_file_conversion() {
    const char *binary_input = "../../../data/input/test_binary.dat";
    const char *base64_output = "../../../data/output/test_base64.txt";
    const char *binary_reconstructed = "../../../data/output/test_binary_reconstructed.dat";

    // Open the binary input file for reading
    FILE *input_file = fopen(binary_input, "r");
    if (input_file == NULL) {
        perror("Error opening binary input file");
        return;  // Exit if file can't be opened
    }

    // Convert binary to Base64
    if (convert_binary_to_base64(binary_input, base64_output) == 0) {
        printf("Binary to Base64 conversion successful.\n");
    } else {
        printf("Binary to Base64 conversion failed.\n");
    }

    fclose(input_file);  // Close the input file after reading

    // Open the Base64 output file for reading
    FILE *output_file = fopen(base64_output, "r");
    if (output_file == NULL) {
        perror("Error opening Base64 output file for reading");
        return;  // Exit if file can't be opened
    }

    // Convert Base64 back to binary
    if (convert_base64_to_binary(base64_output, binary_reconstructed) == 0) {
        printf("Base64 to Binary conversion successful.\n");
    } else {
        printf("Base64 to Binary conversion failed.\n");
    }

    fclose(output_file);  // Close the Base64 output file
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    test_rsa_single_byte();
    test_rsa_multiple_bytes();
    test_rsa_empty_message();
    test_rsa_long_message();
    test_rsa_8_bytes_message();
    printf("Tous les tests phase 1.1 réussis.\n");
    test_base64_file_conversion();
    printf("Le test de la phase 1.3 réussi.\n");
    return 0;
}
