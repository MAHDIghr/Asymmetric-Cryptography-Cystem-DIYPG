/// \file contact.c
/// \author Oliver SEARLE
/// \date avril 2025

#include "../../include/contact.h"
#include <stdio.h>
#include <string.h>

Contact annuaire_contacts[MAX_CONTACTS];
int nb_contacts;

// === Contacts ===

void init_contact(Contact* c, const char* id) {
    strncpy(c->id, id, sizeof(c->id));
    c->id[sizeof(c->id) - 1] = '\0';  // sécurité

    c->nom[0] = '\0';
    c->prenom[0] = '\0';
    c->comment[0] = '\0';
    c->type[0] = '\0';
    c->nb_clefs = 0;
}

void liberer_contact(Contact* c) {
    for (int i = 0; i < c->nb_clefs; i++) {
        mpz_clears(c->clefs[i].n, c->clefs[i].e, NULL);
    }
    c->nb_clefs = 0;
}

void ajouter_contact(const char* id) {
    if (nb_contacts >= MAX_CONTACTS) {
        printf("Trop de contacts.\n");
        return;
    }
    init_contact(&annuaire_contacts[nb_contacts], id);

    printf("Nom : ");
    fgets(annuaire_contacts[nb_contacts].nom, sizeof(annuaire_contacts[nb_contacts].nom), stdin);
    annuaire_contacts[nb_contacts].nom[strcspn(annuaire_contacts[nb_contacts].nom, "\n")] = 0;

    printf("Prénom : ");
    fgets(annuaire_contacts[nb_contacts].prenom, sizeof(annuaire_contacts[nb_contacts].prenom), stdin);
    annuaire_contacts[nb_contacts].prenom[strcspn(annuaire_contacts[nb_contacts].prenom, "\n")] = 0;

    printf("Commentaire : ");
    fgets(annuaire_contacts[nb_contacts].comment, sizeof(annuaire_contacts[nb_contacts].comment), stdin);
    annuaire_contacts[nb_contacts].comment[strcspn(annuaire_contacts[nb_contacts].comment, "\n")] = 0;

    printf("Type (perso / pro) : ");
    fgets(annuaire_contacts[nb_contacts].type, sizeof(annuaire_contacts[nb_contacts].type), stdin);
    annuaire_contacts[nb_contacts].type[strcspn(annuaire_contacts[nb_contacts].type, "\n")] = 0;

    nb_contacts++;
    printf("Contact '%s' ajouté.\n", id);
}


void lister_contacts(const char* id, const char* nom) {
    for (int i = 0; i < nb_contacts; i++) {
        if ((id && strcmp(annuaire_contacts[i].id, id) == 0) ||
            (nom && strcmp(annuaire_contacts[i].nom, nom) == 0) ||
            (!id && !nom)) {
            printf("ID: %s | Nom: %s %s | Commentaire: %s\n",
                   annuaire_contacts[i].id,
                   annuaire_contacts[i].prenom,
                   annuaire_contacts[i].nom,
                   annuaire_contacts[i].comment);
            for (int j = 0; j < annuaire_contacts[i].nb_clefs; j++) {
                printf("  > Clé: %s (%s)\n",
                    annuaire_contacts[i].clefs[j].id,
                    annuaire_contacts[i].clefs[j].type);
            }
        }
    }
}


void modifier_contact(const char* id) {
    for (int i = 0; i < nb_contacts; i++) {
        if (strcmp(annuaire_contacts[i].id, id) == 0) {
            printf("Modification de %s\n", id);
            printf("Nouveau commentaire : ");
            fgets(annuaire_contacts[i].comment, sizeof(annuaire_contacts[i].comment), stdin);
            annuaire_contacts[i].comment[strcspn(annuaire_contacts[i].comment, "\n")] = 0;
            printf("Commentaire mis à jour.\n");
            return;
        }
    }
    printf("Contact non trouvé.\n");
}

void ajouter_cle_contact(const char* id) {
    for (int i = 0; i < nb_contacts; i++) {
        if (strcmp(annuaire_contacts[i].id, id) == 0 || strcmp(annuaire_contacts[i].nom, id) == 0) {
            if (annuaire_contacts[i].nb_clefs >= MAX_CLEFS_CONTACT) {
                printf("Trop de clefs pour ce contact.\n");
                return;
            }
            printf("ID de la nouvelle clef : ");
            fgets(annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].id, 100, stdin);
            annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].id[strcspn(annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].id, "\n")] = 0;

            printf("Type (crypt / sign) : ");
            fgets(annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].type, 10, stdin);
            annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].type[strcspn(annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].type, "\n")] = 0;

            mpz_inits(annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].n, annuaire_contacts[i].clefs[annuaire_contacts[i].nb_clefs].e, NULL);
            annuaire_contacts[i].nb_clefs++;

            printf("Clé ajoutée.\n");
            return;
        }
    }
    printf("Contact non trouvé.\n");
}

void supprimer_contact(const char* id) {
    for (int i = 0; i < nb_contacts; i++) {
        if (strcmp(annuaire_contacts[i].id, id) == 0) {
            liberer_contact(&annuaire_contacts[i]);
            annuaire_contacts[i] = annuaire_contacts[--nb_contacts];
            printf("Contact supprimé.\n");
            return;
        }
    }
    printf("Contact non trouvé.\n");
}