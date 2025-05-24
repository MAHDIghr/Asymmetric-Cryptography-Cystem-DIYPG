/// \file bezout.h
/// \author Oliver SEARLE
/// \date mars 2025
#ifndef RSA_TOOLS_H
#define RSA_TOOLS_H

#include "rsa_common_header.h"
#include <stdint.h>

void initialize_logging();
void erreur(char* msg);
uint64_t random_uint(uint64_t min,uint64_t max);
int premier (uint64_t n);
int decompose (uint64_t facteur[], uint64_t n);
uint64_t puissance(uint64_t a, uint64_t e);
uint64_t puissance_mod_n (uint64_t a, uint64_t e, uint64_t n);
uint64_t genereUint(uint64_t max,int *cpt);
int rabin (uint64_t a, uint64_t n);
int64_t genereUintRabin(uint64_t max,int *cpt);
uint64_t pgcdFast(uint64_t a,uint64_t b);
void genKeysRabin(rsaKey_t *pubKey,rsaKey_t *privKey,uint64_t max_prime);
void inputKey(uint64_t E,uint64_t N,rsaKey_t *key);
void verifRabin(uint64_t max,int iterations);

#endif
