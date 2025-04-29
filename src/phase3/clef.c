#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "../../include/clef.h"

Clef annuaire[MAX_CLEFS];
int nb_clefs = 0;

void init_clef(Clef *c, const char *id, const char *type) {
    strncpy(c->id, id, sizeof(c->id));
    strncpy(c->type, type, sizeof(c->type));
    mpz_inits(c->n, c->e, c->d, NULL);
}

void liberer_clef(Clef *c) {
    mpz_clears(c->n, c->e, c->d, NULL);
}

Clef* chercher_clef(const char* id) {
    for (int i = 0; i < nb_clefs; i++) {
        if (strcmp(annuaire[i].id, id) == 0)
            return &annuaire[i];
    }
    return NULL;
}

void afficher_clef(Clef *c, const char* quoi) {
    /// \brief Affiche les clefs dans un format lisible.
    // affichela clé publique ou privée en fonction de quoi.
    printf("Identifiant: %s (type: %s)\n", c->id, c->type);
    if (strcmp(quoi, "pub") == 0 || strcmp(quoi, "all") == 0) {
        gmp_printf("e: %Zd\nn: %Zd\n", c->e, c->n);
    }
    if (strcmp(quoi, "priv") == 0 || strcmp(quoi, "all") == 0) {
        gmp_printf("d: %Zd\n", c->d);
    }
}
