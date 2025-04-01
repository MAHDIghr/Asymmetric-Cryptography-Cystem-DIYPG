#include "../../../include/phase1.h"
#include "../../../include/rsa_common_header.h"
#include "../../../include/rsa_tools.h"
#include "../../../include/other_base64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Clés RSA d'exemple (petites valeurs pour les tests)
rsaKey_t pubKey = {65537, 3233};  // Clé publique (exemple)
rsaKey_t privKey = {413, 3233};   // Clé privée (exemple)

// Test : chiffrement et déchiffrement d'un seul octet
void test_rsa_single_byte() {
    uint8_t input = 42;  // Valeur d'entrée
    uint8_t encrypted, decrypted;  // Variables pour les résultats

    rsa_encrypt(&input, 1, &encrypted, &pubKey);  // Chiffrement
    rsa_decrypt(&encrypted, 1, &decrypted, &privKey);  // Déchiffrement

    // Affichage du test et vérification
    printf("Test sur un seul octet : entrée=%d, chiffré=%d, déchiffré=%d\n", input, encrypted, decrypted);
    assert(input == decrypted);  // Vérifie si le déchiffrement est correct
}

// Test : chiffrement et déchiffrement d'un tableau de plusieurs octets
void test_rsa_multiple_bytes() {
    uint8_t input[] = {10, 20, 30, 40, 50};  // Données d'entrée
    uint8_t encrypted[5], decrypted[5];  // Buffers pour le chiffrement et le déchiffrement

    rsa_encrypt(input, 5, encrypted, &pubKey);  // Chiffrement
    rsa_decrypt(encrypted, 5, decrypted, &privKey);  // Déchiffrement

    // Affichage des résultats et vérification
    printf("Test sur plusieurs octets : ");
    for (int i = 0; i < 5; i++) {
        printf("%d->%d->%d  ", input[i], encrypted[i], decrypted[i]);
        assert(input[i] == decrypted[i]);  // Vérifie chaque octet
    }
    printf("\n");
}

// Test : entrée vide
void test_rsa_empty_input() {
    uint8_t input[1] = {};  // Tableau vide
    uint8_t encrypted[1], decrypted[1];  // Buffers

    rsa_encrypt(input, 0, encrypted, &pubKey);  // Chiffrement (devrait ne rien faire)
    rsa_decrypt(encrypted, 0, decrypted, &privKey);  // Déchiffrement

    printf("Test avec une entrée vide réussi.\n");  // Vérification réussie si pas d'erreur
}

// Test : chiffrement et déchiffrement de la valeur maximale possible (255)
void test_rsa_max_value() {
    uint8_t input = 255;  // Valeur maximale d'un uint8_t
    uint8_t encrypted, decrypted;  // Buffers

    rsa_encrypt(&input, 1, &encrypted, &pubKey);  // Chiffrement
    rsa_decrypt(&encrypted, 1, &decrypted, &privKey);  // Déchiffrement

    // Affichage et vérification
    printf("Test sur la valeur maximale : entrée=%d, chiffré=%d, déchiffré=%d\n", input, encrypted, decrypted);
    assert(input == decrypted);
}

// Fonction principale exécutant tous les tests
int main() {
    test_rsa_single_byte();
    test_rsa_multiple_bytes();
    test_rsa_empty_input();
    test_rsa_max_value();

    printf("\n Tous les tests unitaires RSA ont réussi avec succès !\n");
    return 0;
}
