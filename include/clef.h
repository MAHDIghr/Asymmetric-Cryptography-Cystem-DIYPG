#ifndef CLEF_H
#define CLEF_H

#include <gmp.h>

#define MAX_CLEFS 100

typedef struct {
    char id[100];
    char type[10]; // "crypt" ou "sign"
    mpz_t n, e, d;
} Clef;

extern Clef annuaire[MAX_CLEFS];
extern int nb_clefs;

void init_clef(Clef *c, const char *id, const char *type);
void liberer_clef(Clef *c);
Clef* chercher_clef(const char* id);
void afficher_clef(Clef *c, const char* quoi);

#endif
