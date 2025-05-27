/// \file bezout.h
/// \author Oliver SEARLE
/// \date mars 2025
#ifndef BEZOUT_H
#define BEZOUT_H
#include <stdint.h>

int64_t bezout(uint64_t a,uint64_t b,int64_t *u,int64_t *v);

int64_t bezoutRSA(uint64_t a,uint64_t b,int64_t *u,int64_t *v);


#endif