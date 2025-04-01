/// \file phase1.h
/// \author Oliver SEARLE
/// \date mars 2025
#ifndef PHASE1_H
#define PHASE1_H

#include "rsa_common_header.h"
#include <stdint.h>

void printKey(const rsaKey_t *key);

void printKeyPair(const keyPair_t *keyPair);

void rsa_encrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *pubKey);

void rsa_decrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *privKey);

char *convert_binary_to_base64(const unsigned char *data, size_t input_length);

unsigned char *convert_base64_to_binary(const char *base64_string, size_t *output_length);

#endif