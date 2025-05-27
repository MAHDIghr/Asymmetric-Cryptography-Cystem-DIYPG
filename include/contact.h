#ifndef CONTACT_H
#define CONTACT_H

#include <gmp.h>

#define MAX_CONTACTS 100
#define MAX_CLEFS_CONTACT 10

typedef struct {
    char id[100];
    char type[10];
    mpz_t n, e;
} ClefContact;

typedef struct {
    char id[100];
    char nom[100];
    char prenom[100];
    char comment[200];
    char type[20];
    ClefContact clefs[MAX_CLEFS_CONTACT];
    int nb_clefs;
} Contact;

void init_contact(Contact* c, const char* id);
void liberer_contact(Contact* c);

void ajouter_contact(const char* id);
void lister_contacts(const char* id, const char* nom);
void modifier_contact(const char* id);
void ajouter_cle_contact(const char* id);
void supprimer_contact(const char* id);

extern Contact annuaire_contacts[MAX_CONTACTS];
extern int nb_contacts;

#endif
