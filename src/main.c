#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "../include/phase1.h"
#include "../include/phase2.h"
#include "../include/rsa_tools.h"

#define TEST_FILE "test_data.txt"
#define ENCRYPTED_FILE "encrypted.bin"
#define DECRYPTED_FILE "decrypted.txt"
#define BASE64_FILE "base64.txt"
#define KEY_FILE "key.pub"

/* ==================== */
/*  Fonctions utilitaires */
/* ==================== */

// Affiche un titre de section
void print_section(const char* title) {
    printf("\n=== %s ===\n", title);
}

// Crée un fichier de test avec du texte
void create_test_file() {
    FILE* f = fopen(TEST_FILE, "w");
    if (!f) {
        perror("Erreur création fichier test");
        exit(EXIT_FAILURE);
    }
    fprintf(f, "Ceci est un message de test pour le projet DIYPG!\n");
    fclose(f);
}

/* ==================== */
/*  Démonstrations Phase 1 */
/* ==================== */

void demo_phase1() {
    print_section("Phase 1 : Chiffrement de base");

    // 1. Génération des clés
    rsaKey_t pubKey, privKey;
    genKeysRabin(&pubKey, &privKey, 10000);
    
    printf("Clés générées :\n");
    print_rsa_key(&pubKey, "publique");
    print_rsa_key(&privKey, "privée");

    // 2. Chiffrement caractère par caractère
    const char* message = "HELLO";
    size_t len = strlen(message);
    
    uint8_t* encrypted = encrypt_tab((uint8_t*)message, len, &pubKey);
    uint8_t* decrypted = decrypt_tab(encrypted, len, &privKey);
    
    printf("\nChiffrement caractère par caractère :\n");
    printf("Original: %s\n", message);
    printf("Chiffré: [");
    for (size_t i = 0; i < len; i++) printf("%02X ", encrypted[i]);
    printf("]\n");
    printf("Déchiffré: %s\n", decrypted);

    free(encrypted);
    free(decrypted);

    // 3. Conversion Base64
    char* base64 = convert_binary_to_base64((unsigned char*)message, len);
    printf("\nConversion Base64 :\n%s\n", base64);
    free(base64);
}

/* ==================== */
/*  Démonstrations Phase 2 */
/* ==================== */

void demo_phase2() {
    print_section("Phase 2 : Chiffrement par blocs avec GMP");

    // 1. Initialisation GMP
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);
    
    // Valeurs de test (en pratique: générées avec genKeysRabin)
    mpz_set_str(n, "9516311845790656153499716760847001433441357", 10);
    mpz_set_str(e, "65537", 10);
    mpz_set_str(d, "5617843187844953170308463622230283376298685", 10);

    // 2. Chiffrement d'un bloc
    mpz_t msg, chiffre, dechiffre;
    mpz_inits(msg, chiffre, dechiffre, NULL);
    mpz_set_ui(msg, 0x61626364); // "abcd" en hexa
    
    rsa_chiffrer_bloc(chiffre, msg, e, n);
    rsa_dechiffrer_bloc(dechiffre, chiffre, d, n);
    
    printf("\nChiffrement bloc (4 octets):\n");
    gmp_printf("Original: %Zd\n", msg);
    gmp_printf("Chiffré: %Zd\n", chiffre);
    gmp_printf("Déchiffré: %Zd\n", dechiffre);

    // 3. Chiffrement de fichier
    create_test_file();
    
    printf("\nChiffrement fichier...\n");
    rsa_chiffrer_fichier(TEST_FILE, ENCRYPTED_FILE, e, n);
    rsa_dechiffrer_fichier(ENCRYPTED_FILE, DECRYPTED_FILE, d, n);
    
    printf("Fichier déchiffré comparé à l'original : ");
    FILE* f1 = fopen(TEST_FILE, "r");
    FILE* f2 = fopen(DECRYPTED_FILE, "r");
    if (f1 && f2) {
        int c1, c2, ok = 1;
        while ((c1 = fgetc(f1)) != EOF && (c2 = fgetc(f2)) != EOF) {
            if (c1 != c2) ok = 0;
        }
        printf(ok ? "OK\n" : "DIFFÉRENT\n");
    }
    if (f1) fclose(f1);
    if (f2) fclose(f2);

    // 4. Export Base64
    printf("\nExport clé publique en Base64:\n");
    char* cle_b64 = exporter_cle_publique_base64(n, e);
    printf("%s\n", cle_b64);
    
    FILE* key_file = fopen(KEY_FILE, "w");
    if (key_file) {
        fprintf(key_file, "%s", cle_b64);
        fclose(key_file);
    }
    free(cle_b64);

    // Nettoyage
    mpz_clears(n, e, d, msg, chiffre, dechiffre, NULL);
}

/* ==================== */
/*  Programme principal */
/* ==================== */

int main() {
    printf("=== Démonstration complète DIYPG ===\n");
    
    demo_phase1();
    demo_phase2();

    printf("\n=== Fin de la démonstration ===\n");
    return 0;
}