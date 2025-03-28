/// \file phase1.h
/// \author Oliver SEARLE
/// \date mars 2025
#ifndef PHASE1_H
#define PHASE1_H
#include "file_io.h"
#include "rsa_common_header.h"
#include "../src/core/rsa_tools.c"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void rsa_encrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *pubKey);

void rsa_decrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *privKey);

#endif