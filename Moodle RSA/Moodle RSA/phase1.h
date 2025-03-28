/// \file phase1.h
/// \author Oliver SEARLE
/// \date mars 2025
#ifndef PHASE1_H
#define PHASE1_H

void rsa_encrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *pubKey);

void rsa_decrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *privKey);

#endif
