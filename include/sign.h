#ifndef SIGN_H
#define SIGN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "clef.h"
#include "sha256.h"
#define BUFFER_SIZE 512

int hash_fichier_sha256(const char *chemin_fichier, BYTE hash[32]);
void chiffrer_hash(mpz_t chiffré, const BYTE hash[32], Clef* clef_publique);
void dechiffrer_hash(mpz_t hash_dechiffre, mpz_t hash_chiffre, Clef* clef_privee);
void signer_hash(mpz_t signature, const BYTE hash[32], Clef *clef_privee);
void signer_fichier(const char* filein, const char* fileout, const char* keyid_sign, const char* keyid_chiffre);
int verifier_signature(const char* filein, const char* filesign, const char* keyid_sign, const char* keyid_chiffre);

#endif
