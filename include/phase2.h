/// \file phase2.h
/// \author Oliver SEARLE
/// \date mars 2025
#ifndef PHASE2_H
#define PHASE2_H

#include <gmp.h>
#include "rsa_common_header.h"
#include <stdint.h>

void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n);

void rsa_chiffrer_bloc(mpz_t res, const mpz_t message, const mpz_t e, const mpz_t n);

void rsa_dechiffrer_bloc(mpz_t res, const mpz_t chiffré, const mpz_t d, const mpz_t n);

void rsa_chiffrer_fichier(const char* chemin_in, const char* chemin_out, const mpz_t e, const mpz_t n);

void rsa_dechiffrer_fichier(const char* chemin_in, const char* chemin_out, const mpz_t d, const mpz_t n);

char* exporter_cle_publique_base64(const mpz_t n, const mpz_t e);

void fichier_binaire_vers_base64(const char* chemin_in, const char* chemin_out);

void fichier_base64_vers_binaire(const char* chemin_in, const char* chemin_out);

void charger_cle_publique(const char *fichier, mpz_t e, mpz_t n);

void charger_cle_privee(const char *fichier, mpz_t d, mpz_t n);

#endif