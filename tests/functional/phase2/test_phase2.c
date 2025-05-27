#include <gmp.h>
#include "../../../include/phase2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Fonction pour comparer deux fichiers

#define BUFFER_SIZE 4096

int comparer_fichiers(const char *fichier1, const char *fichier2) {
    FILE *fp1 = fopen(fichier1, "rb");
    FILE *fp2 = fopen(fichier2, "rb");
    if (!fp1 || !fp2) {
        perror("Erreur ouverture fichier pour comparaison");
        if (fp1) fclose(fp1);
        if (fp2) fclose(fp2);
        return 0;
    }

    unsigned char buffer1[BUFFER_SIZE];
    unsigned char buffer2[BUFFER_SIZE];
    size_t r1, r2;
    int result = 1;

    while (1) {
        r1 = fread(buffer1, 1, BUFFER_SIZE, fp1);
        r2 = fread(buffer2, 1, BUFFER_SIZE, fp2);

        if (r1 != r2 || memcmp(buffer1, buffer2, r1) != 0) {
            result = 0;
            break;
        }

        if (r1 < BUFFER_SIZE) break; // fin de fichier atteinte
    }

    fclose(fp1);
    fclose(fp2);
    return result;
}

int main() {
    printf("Début des tests...\n");

    // ---------------- Initialisation des clés pour les tests ----------------
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    // Petites valeurs pour tests rapides
    mpz_set_str(n, "9516311845790656153499716760847001433441357", 10);
    mpz_set_str(e, "65537", 10);
    mpz_set_str(d, "5617843187844953170308463622230283376298685", 10);

    // ---------------- Test 1 : Chiffrement et déchiffrement d'un bloc ----------------
    printf("[Test 1] Chiffrement/Déchiffrement d'un bloc... ");

    mpz_t message, chiffré, dechiffré;
    mpz_inits(message, chiffré, dechiffré, NULL);

    mpz_set_ui(message, 123); // Exemple de petit message à chiffrer

    rsa_chiffrer_bloc(chiffré, message, e, n);
    rsa_dechiffrer_bloc(dechiffré, chiffré, d, n);

    if (mpz_cmp(message, dechiffré) == 0) {
        printf("OK\n");
    } else {
        printf("ÉCHEC\n");
    }

    mpz_clears(message, chiffré, dechiffré, NULL);

    // ---------------- Test 2 : Chiffrement et déchiffrement d'un fichier ----------------
    printf("[Test 2] Chiffrement/Déchiffrement d'un fichier... ");

    // Créer un fichier temporaire avec du contenu
    FILE *f = fopen("data/input/test_in.txt", "wb");
    if (!f) { perror("fopen test_in.txt"); exit(EXIT_FAILURE); }
    const char *texte = "Bonjour, ceci est un test.";
    fwrite(texte, 1, strlen(texte), f);
    fclose(f);

    // Chiffrer
    rsa_chiffrer_fichier("data/input/test_in.txt", "data/output/test_chiffre.txt", e, n);

    // Déchiffrer
    rsa_dechiffrer_fichier("data/output/test_chiffre.txt", "data/output/test_out.txt", d, n);

    if (comparer_fichiers("data/input/test_in.txt", "data/output/test_out.txt")) {
        printf("OK\n");
    } else {
        printf("ÉCHEC\n");
    }

    // ---------------- Test 3 : Conversion base64 aller-retour ----------------
    printf("[Test 3] Conversion Base64 aller-retour... ");

    fichier_binaire_vers_base64("data/input/binary.txt", "data/output/base64.txt");
    fichier_base64_vers_binaire("data/output/base64.txt", "data/output/binary_copy.txt");

    if (comparer_fichiers("data/input/binary.txt", "data/output/binary_copy.txt")) {
        printf("OK\n");
    } else {
        printf("ÉCHEC\n");
    }

    // ---------------- Nettoyage ----------------
    mpz_clears(n, e, d, NULL);

    remove("data/input/test_in.txt");
    remove("data/output/test_chiffre.txt");
    remove("data/output/test_out.txt");
    remove("data/output/base64.txt");
    remove("data/output/binary_copy.txt");

    printf("Tous les tests terminés.\n");


    return 0;
}



