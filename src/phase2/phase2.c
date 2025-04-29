#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/phase1.h"

void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n) {
    mpz_t base, exposant, modulo;

    // Initialiser les variables GMP
    mpz_init_set_ui(base, a);      // base = a
    mpz_init_set_ui(exposant, e);  // exposant = e
    mpz_init_set_ui(modulo, n);    // modulo = n

    // Calcul de res = (base^exposant) mod modulo
    mpz_powm(res, base, exposant, modulo);

    // Libérer la mémoire
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
        return;
    }

    uint8_t buffer;
    while (fread(&buffer, 1, 1, fin) == 1) {
        mpz_t message, chiffré;
        mpz_init_set_ui(message, buffer);
        mpz_init(chiffré);

        rsa_chiffrer_bloc(chiffré, message, e, n);

        size_t size;
        uint8_t *bin = (uint8_t *) mpz_export(NULL, &size, 1, 1, 0, 0, chiffré);
        uint8_t size8 = (uint8_t) size;
        fwrite(&size8, 1, 1, fout);  
        fwrite(bin, 1, size, fout);

        free(bin);
        mpz_clear(message);
        mpz_clear(chiffré);
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
        return;
    }

    while (!feof(fin)) {
        uint8_t size8;
        if (fread(&size8, 1, 1, fin) != 1) break;

        uint8_t *bin = malloc(size8);
        if (fread(bin, 1, size8, fin) != size8) {
            free(bin);
            break;
        }

        mpz_t chiffré, message;
        mpz_init(chiffré);
        mpz_init(message);
        mpz_import(chiffré, size8, 1, 1, 0, 0, bin);

        rsa_dechiffrer_bloc(message, chiffré, d, n);

        uint64_t valeur = mpz_get_ui(message);
        uint8_t octet = (uint8_t) valeur;
        fwrite(&octet, 1, 1, fout);

        mpz_clear(chiffré);
        mpz_clear(message);
        free(bin);
    }

    fclose(fin);
    fclose(fout);
}



//D


char* exporter_cle_publique_base64(const mpz_t n, const mpz_t e) {
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


//#####################################################" CHargement clés"

void charger_cle_publique(const char *fichier, mpz_t e, mpz_t n) {
    FILE *fp = fopen(fichier, "r");
    if (!fp) {
        perror("Erreur ouverture fichier clé publique");
        exit(EXIT_FAILURE);
    }
    char ligne[1024];
    while (fgets(ligne, sizeof(ligne), fp)) {
        if (ligne[0] == 'e') {
            mpz_set_str(e, ligne + 2, 10);  // sauter "e="
        } else if (ligne[0] == 'n') {
            mpz_set_str(n, ligne + 2, 10);  // sauter "n="
        }
    }
    fclose(fp);
}

void charger_cle_privee(const char *fichier, mpz_t d, mpz_t n) {
    FILE *fp = fopen(fichier, "r");
    if (!fp) {
        perror("Erreur ouverture fichier clé privée");
        exit(EXIT_FAILURE);
    }
    char ligne[1024];
    while (fgets(ligne, sizeof(ligne), fp)) {
        if (ligne[0] == 'd') {
            mpz_set_str(d, ligne + 2, 10);  // sauter "d="
        } else if (ligne[0] == 'n') {
            mpz_set_str(n, ligne + 2, 10);  // sauter "n="
        }
    }
    fclose(fp);
}























