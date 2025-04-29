#include <gmp.h>
#include "../../../include/phase2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Fonction pour comparer deux fichiers
int comparer_fichiers(const char *fichier1, const char *fichier2) {
    FILE *fp1 = fopen(fichier1, "rb");
    FILE *fp2 = fopen(fichier2, "rb");
    if (!fp1 || !fp2) {
        perror("Erreur ouverture fichier pour comparaison");
        return 0;
    }

    int result = 1; // supposons qu'ils sont égaux
    int c1, c2;
    while ((c1 = fgetc(fp1)) != EOF && (c2 = fgetc(fp2)) != EOF) {
        if (c1 != c2) {
            result = 0;
            break;
        }
    }

    // Vérifier aussi la fin de fichier
    if (c1 != c2) result = 0;

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
    FILE *f = fopen("test_in.txt", "wb");
    if (!f) { perror("fopen test_in.txt"); exit(EXIT_FAILURE); }
    const char *texte = "Bonjour, ceci est un test.";
    fwrite(texte, 1, strlen(texte), f);
    fclose(f);

    // Chiffrer
    rsa_chiffrer_fichier("test_in.txt", "test_chiffre.bin", e, n);

    // Déchiffrer
    rsa_dechiffrer_fichier("test_chiffre.bin", "test_out.txt", d, n);

    if (comparer_fichiers("test_in.txt", "test_out.txt")) {
        printf("OK\n");
    } else {
        printf("ÉCHEC\n");
    }

    // ---------------- Test 3 : Conversion base64 aller-retour ----------------
    printf("[Test 3] Conversion Base64 aller-retour... ");

    fichier_binaire_vers_base64("test_chiffre.bin", "test_chiffre_base64.txt");
    fichier_base64_vers_binaire("test_chiffre_base64.txt", "test_chiffre_reconverti.bin");

    if (comparer_fichiers("test_chiffre.bin", "test_chiffre_reconverti.bin")) {
        printf("OK\n");
    } else {
        printf("ÉCHEC\n");
    }

    // ---------------- Nettoyage ----------------
    mpz_clears(n, e, d, NULL);

    remove("test_in.txt");
    remove("test_chiffre.bin");
    remove("test_out.txt");
    remove("test_chiffre_base64.txt");
    remove("test_chiffre_reconverti.bin");

    printf("Tous les tests terminés.\n");

    return 0;
}



