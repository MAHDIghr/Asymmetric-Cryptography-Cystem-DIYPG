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

void test_rsa_encrypt_decrypt() {
    rsaKey_t pubKey, privKey;
    genKeysRabin(&pubKey, &privKey, 257);
    
    uint8_t input[] = "HELLO WORLD";
    uint64_t length = strlen((char *)input);
    uint8_t encrypted[length];
    uint8_t decrypted[length];
    
    rsa_encrypt(input, length, encrypted, &pubKey);
    rsa_decrypt(encrypted, length, decrypted, &privKey);
    
    assert(memcmp(input, decrypted, length) == 0);
    printf("Test de base réussi.\n");
}

void test_rsa_special_characters() {
    rsaKey_t pubKey, privKey;
    genKeysRabin(&pubKey, &privKey, 257);
    
    uint8_t input[] = "!@#$%^&*()";
    uint64_t length = strlen((char *)input);
    uint8_t encrypted[length];
    uint8_t decrypted[length];
    
    rsa_encrypt(input, length, encrypted, &pubKey);
    rsa_decrypt(encrypted, length, decrypted, &privKey);
    
    assert(memcmp(input, decrypted, length) == 0);
    printf("Test des caractères spéciaux réussi.\n");
}

void test_rsa_binary_data() {
    rsaKey_t pubKey, privKey;
    genKeysRabin(&pubKey, &privKey, 257);
    
    uint8_t input[] = {0x00, 0xFF, 0x7F, 0x80};
    uint64_t length = sizeof(input);
    uint8_t encrypted[length];
    uint8_t decrypted[length];
    
    rsa_encrypt(input, length, encrypted, &pubKey);
    rsa_decrypt(encrypted, length, decrypted, &privKey);
    
    assert(memcmp(input, decrypted, length) == 0);
    printf("Test des données binaires réussi.\n");
}

void test_rsa_empty_input() {
    rsaKey_t pubKey, privKey;
    genKeysRabin(&pubKey, &privKey, 257);
    
    uint8_t input[] = "";
    uint64_t length = strlen((char *)input);
    uint8_t encrypted[1];
    uint8_t decrypted[1];
    
    rsa_encrypt(input, length, encrypted, &pubKey);
    rsa_decrypt(encrypted, length, decrypted, &privKey);
    
    assert(length == 0);
    printf("Test avec entrée vide réussi.\n");
}

int main() {
    test_rsa_encrypt_decrypt();
    test_rsa_special_characters();
    test_rsa_binary_data();
    test_rsa_empty_input();
    printf("Tout les tests phase 1.1 passés\n");
    return 0;
}
