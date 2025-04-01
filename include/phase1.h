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

int convert_binary_to_base64(const char *input_filename, const char *output_filename);

int convert_base64_to_binary(const char *input_file, const char *output_file);

#endif