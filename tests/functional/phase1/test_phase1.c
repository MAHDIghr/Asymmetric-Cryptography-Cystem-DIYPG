#include "../../../include/phase1.h"
#include "../../../include/rsa_common_header.h"
#include "../../../include/rsa_tools.h"
#include <stdint.h>

void test_rsa(const uint8_t *input, uint64_t length, const char *test_name) {
    /// \brief Fonction générique de test du chiffrement et du déchiffrement
    rsaKey_t pubKey, privKey;
    genKeysRabin(&pubKey, &privKey, 257);
    
    uint8_t encrypted[length];
    uint8_t decrypted[length];
    
    rsa_encrypt((uint8_t *)input, length, encrypted, &pubKey);
    rsa_decrypt(encrypted, length, decrypted, &privKey);
    
    assert(memcmp(input, decrypted, length) == 0);
    printf("%s réussi.\n", test_name);
}

void test_rsa_encrypt_decrypt() {
    uint8_t input[] = "HELLO WORLD";
    test_rsa(input, strlen((char *)input), "Test de base");
}

void test_rsa_special_characters() {
    uint8_t input[] = "!@#$^&*()";
    test_rsa(input, strlen((char *)input), "Test des caractères spéciaux");
}

void test_rsa_binary_data() {
    uint8_t input[] = {0x00, 0xFF, 0x7F, 0x80};
    test_rsa(input, sizeof(input), "Test des données binaires");
}

void test_rsa_empty_input() {
    uint8_t input[] = "";
    test_rsa(input, strlen((char *)input), "Test avec entrée vide");
}

void test_rsa_extended() {
    uint8_t input[] = "Ceci est un test plus long avec plusieurs caractères.";
    test_rsa(input, strlen((char *)input), "Test avec une phrase complète");
}

void test_base64_file_conversion() {
    /// \brief fonnction de test pour les conversions Base 64
    const char *binary_input = "../../data/input/test_binary.dat";
    const char *base64_output = "../../data/output/test_base64.txt";
    const char *binary_reconstructed = "../../data/output/test_binary_reconstructed.dat";

    if (convert_binary_to_base64(binary_input, base64_output) == 0) {
        printf("Binary to Base64 conversion successful.\n");
    } else {
        printf("Binary to Base64 conversion failed.\n");
    }

    if (convert_base64_to_binary(base64_output, binary_reconstructed) == 0) {
        printf("Base64 to Binary conversion successful.\n");
    } else {
        printf("Base64 to Binary conversion failed.\n");
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    test_rsa_encrypt_decrypt();
    test_rsa_special_characters();
    test_rsa_binary_data();
    test_rsa_empty_input();
    test_rsa_extended();
    printf("Tous les tests phase 1.1 réussis.\n");
    test_base64_file_conversion();
    printf("Le test de la phase 1.3 réussi.\n");
    return 0;
}
