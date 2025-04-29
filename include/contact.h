// contact.h
#ifndef CONTACT_H
#define CONTACT_H

#include <gmp.h>

#define MAX_CLEFS_CONTACT 10
#define MAX_CONTACTS 100

typedef struct {
    char id[100];
    char type[10]; // "crypt" ou "sign"
    mpz_t n, e;
} ClefContact;

typedef struct {
    char id[100];
    char type[10];
    char nom[100];
    char prenom[100];
    char comment[256];
    int nb_clefs;
    ClefContact clefs[MAX_CLEFS_CONTACT];
} Contact;

extern Contact annuaire_contacts[MAX_CONTACTS];
extern int nb_contacts;

void init_contact(Contact* c, const char* id);
void liberer_contact(Contact* c);

#endif // CONTACT_H
