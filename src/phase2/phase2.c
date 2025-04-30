#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/phase1.h"

void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n) {
    /// \brief Initialiser les variables GMP, (base a, exposant e,modulo n)
    // calcul de res = (base^exposant) mod modulo
    mpz_t base, exposant, modulo;

    mpz_init_set_ui(base, a);
    mpz_init_set_ui(exposant, e);
    mpz_init_set_ui(modulo, n);    

    mpz_powm(res, base, exposant, modulo);

    mpz_clear(base);
    mpz_clear(exposant);
    mpz_clear(modulo);
}

//A

void rsa_chiffrer_bloc(mpz_t res, const mpz_t message, const mpz_t e, const mpz_t n) {
    mpz_powm(res, message, e, n);  // res = (message^e) mod n
}

void rsa_dechiffrer_bloc(mpz_t res, const mpz_t chiffré, const mpz_t d, const mpz_t n) {
    mpz_powm(res, chiffré, d, n);  // res = (chiffré^d) mod n
}

//B

void rsa_chiffrer_fichier(const char* chemin_in, const char* chemin_out, const mpz_t e, const mpz_t n) {
    FILE *fin = fopen(chemin_in, "rb");
    FILE *fout = fopen(chemin_out, "wb");
    if (!fin || !fout) {
        perror("Erreur ouverture fichier");
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return;
    }

    uint8_t buffer[4];
    size_t lus;

    while ((lus = fread(buffer, 1, 4, fin)) > 0) {
        // Importer les 4 octets en entier GMP
        mpz_t message, chiffré;
        mpz_init(message);
        mpz_init(chiffré);
        mpz_import(message, lus, 1, 1, 0, 0, buffer);

        // RSA encryption
        rsa_chiffrer_bloc(chiffré, message, e, n);

        // Exporter le résultat
        size_t taille_chiffrée;
        uint8_t *chiffré_bin = (uint8_t *) mpz_export(NULL, &taille_chiffrée, 1, 1, 0, 0, chiffré);

        // Écrire la taille suivie du bloc chiffré
        uint8_t taille8 = (uint8_t) taille_chiffrée;
        fwrite(&taille8, 1, 1, fout);
        fwrite(chiffré_bin, 1, taille_chiffrée, fout);

        free(chiffré_bin);
        mpz_clears(message, chiffré, NULL);
    }

    fclose(fin);
    fclose(fout);
}

//C

void rsa_dechiffrer_fichier(const char* chemin_in, const char* chemin_out, const mpz_t d, const mpz_t n) {
    FILE *fin = fopen(chemin_in, "rb");
    FILE *fout = fopen(chemin_out, "wb");
    if (!fin || !fout) {
        perror("Erreur ouverture fichier");
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return;
    }

    while (1) {
        uint8_t size8;
        size_t lu = fread(&size8, 1, 1, fin);
        if (lu != 1) break;  // fin de fichier

        uint8_t *bin = malloc(size8);
        if (!bin || fread(bin, 1, size8, fin) != size8) {
            free(bin);
            break;
        }

        mpz_t chiffré, message;
        mpz_inits(chiffré, message, NULL);
        mpz_import(chiffré, size8, 1, 1, 0, 0, bin);

        rsa_dechiffrer_bloc(message, chiffré, d, n);

        // Convertit le résultat GMP en tableau de 4 octets max
        size_t taille_bloc;
        uint8_t *plaintext = (uint8_t *) mpz_export(NULL, &taille_bloc, 1, 1, 0, 0, message);
        fwrite(plaintext, 1, taille_bloc, fout);

        mpz_clears(chiffré, message, NULL);
        free(bin);
        free(plaintext);
    }

    fclose(fin);
    fclose(fout);
}

//D

char* exporter_cle_publique_base64(const mpz_t n, const mpz_t e) {
    /// \brief Convertit un clef en binaire puis en Base64
    size_t n_size, e_size;
    uint8_t* n_bin = (uint8_t*) mpz_export(NULL, &n_size, 1, 1, 0, 0, n);
    uint8_t* e_bin = (uint8_t*) mpz_export(NULL, &e_size, 1, 1, 0, 0, e);

    size_t total_size = n_size + e_size + 2;  // 2 bytes pour séparer n et e
    uint8_t* buffer = malloc(total_size);
    memcpy(buffer, n_bin, n_size);
    buffer[n_size] = 0;  // séparateur
    memcpy(buffer + n_size + 1, e_bin, e_size);
    buffer[n_size + e_size + 1] = 0; // séparateur

    char* base64_encoded = convert_binary_to_base64(buffer, total_size);

    free(buffer);
    free(n_bin);
    free(e_bin);

    return base64_encoded;
}

void fichier_binaire_vers_base64(const char* chemin_in, const char* chemin_out) {
    /// \brief convertit un fichier binaire en base64.
    FILE *fin = fopen(chemin_in, "rb");
    FILE *fout = fopen(chemin_out, "w");
    if (!fin || !fout) {
        perror("Erreur ouverture fichier");
        return;
    }

    fseek(fin, 0, SEEK_END);
    long taille = ftell(fin);
    rewind(fin);

    uint8_t *buffer = malloc(taille);
    fread(buffer, 1, taille, fin);

    char *base64_encoded = convert_binary_to_base64(buffer, taille);
    fprintf(fout, "%s", base64_encoded);

    free(buffer);
    free(base64_encoded);
    fclose(fin);
    fclose(fout);
}

void fichier_base64_vers_binaire(const char* chemin_in, const char* chemin_out) {
    /// \brief Convertit un fichier base 64 en fichier binaire.
    FILE *fin = fopen(chemin_in, "r");
    FILE *fout = fopen(chemin_out, "wb");
    if (!fin || !fout) {
        perror("Erreur ouverture fichier");
        return;
    }

    fseek(fin, 0, SEEK_END);
    long taille = ftell(fin);
    rewind(fin);

    char *buffer = malloc(taille + 1);
    fread(buffer, 1, taille, fin);
    buffer[taille] = '\0'; // null-terminate

    size_t sortie_len;
    unsigned char *bin = convert_base64_to_binary(buffer, &sortie_len);

    fwrite(bin, 1, sortie_len, fout);

    free(buffer);
    free(bin);
    fclose(fin);
    fclose(fout);
}
