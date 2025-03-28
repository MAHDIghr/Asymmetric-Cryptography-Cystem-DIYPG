/// \file phase1.c
/// \author Oliver Searle
/// \date Mars 2025
/// \brief Fonctions de Encryption et Decryption

#include "rsa_common_header.h"
#include "rsa_tools.c"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void rsa_encrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *pubKey) {
    /// \brief Encrypt le tableau d'octets input de longueur length avec la clé publique pubKey et retourne le tableau encryptée output
    for (uint64_t i = 0; i < length; i++) {
        output[i] = (uint8_t) puissance_mod_n(input[i], pubKey->E, pubKey->N);
    }
}

void rsa_decrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *privKey) {
    /// \brief Decrypte le tableau d'octets input de longueur length avec la clé privée privKey et retourne le tableau encryptée output
    for (uint64_t i = 0; i < length; i++) {
        output[i] = (uint8_t) puissance_mod_n(input[i], privKey->E, privKey->N);
    }
}

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
    uint8_t input[] = "!@#$%^&*()";
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

int main() {
    test_rsa_encrypt_decrypt();
    test_rsa_special_characters();
    test_rsa_binary_data();
    test_rsa_empty_input();
    test_rsa_extended();
    printf("Tous les tests phase 1.1 réussis.\n");
    return 0;
}
