/// \file phase1.h
/// \author Oliver SEARLE
/// \date mars 2025
#ifndef PHASE1_H
#define PHASE1_H

#include "rsa_common_header.h"
#include <stdint.h>

void printKey(const rsaKey_t *key);

void printKeyPair(const keyPair_t *keyPair);

uint64_t encrypt_char(uint64_t input, rsaKey_t *pubKey);

uint64_t decrypt_char(uint64_t input, rsaKey_t *privKey);

uint8_t* encrypt_tab(uint8_t* input, int length, rsaKey_t* pubKey);

uint8_t* decrypt_tab(uint8_t* input, int length, rsaKey_t* pubKey);

char *convert_binary_to_base64(const unsigned char *data, size_t input_length);

unsigned char *convert_base64_to_binary(const char *base64_string, size_t *output_length);

void convert_file_binary_to_base64(const char *input_file, const char *output_file);

void convert_file_base64_to_binary(const char *input_file, const char *output_file);

#endif