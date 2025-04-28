/// \file interprete.h
/// \author Oliver SEARLE
/// \date avril 2025
// interpreteur.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "../../include/phase2.h"
#include "../../include/rsa_tools.h"
#include "../../include/contact.h"
#include "../../include/phase1.h"
#include "../../include/rsa_common_header.h"
#include "../../include/phase2.h"

#define MAX_CLEFS 100
#define BUFFER_SIZE 512

typedef struct {
    char id[100];
    char type[10]; // "crypt" ou "sign"
    mpz_t n, e, d;
} Clef;

Clef annuaire[MAX_CLEFS];
int nb_clefs = 0;

Contact annuaire_contacts[MAX_CONTACTS];
int nb_contacts = 0;

// === Aide ===

void afficher_aide() {
    printf("\nCommandes disponibles :\n");
    printf("  newkeys <keyid> <type>\n");
    printf("  listkeys [keyid] [pub|priv]\n");
    printf("  rmkeys <keyid>\n");
    printf("  crypt <filein> <fileout> <keyid>\n");
    printf("  uncrypt <filein> <fileout> <keyid>\n");
    printf("  signtext <filein> <keyid> <fileout>\n");
    printf("  verifysign <filein> <filesig> <keyid>\n");
    printf("  save [filename]\n");
    printf("  load [filename]\n");
    printf("  savepub <keyid> <filename>\n");
    printf("  bin-2b64 <filein> <fileout>\n");
    printf("  b64-2bin <filein> <fileout>\n");
    printf("  show <keyid> [pub|priv]\n");
    printf("  certify <keyid>\n");
    printf("  revoke <keyid>\n");
    printf("  listcontacts [id] [nom]\n");
    printf("  addcontact <id>\n");
    printf("  modifycontact <id>\n");
    printf("  addkeys <id>\n");
    printf("  rmcontact <id>\n");
    printf("  quit\n\n");
}

// === Fonctions utilitaires ===

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
//
void sauvegarder_clefs(const char* filename) {
    FILE *f = fopen(filename, "w");
    if (!f) { perror("Erreur sauvegarde"); return; }
    for (int i = 0; i < nb_clefs; i++) {
        fprintf(f, "id=%s\n", annuaire[i].id);
        fprintf(f, "type=%s\n", annuaire[i].type);
        gmp_fprintf(f, "n=%Zd\n", annuaire[i].n);
        gmp_fprintf(f, "e=%Zd\n", annuaire[i].e);
        gmp_fprintf(f, "d=%Zd\n", annuaire[i].d);
    }
    fclose(f);
    printf("Clés sauvegardées dans %s.\n", filename);
}

void charger_clefs(const char* filename) {
    FILE *f = fopen(filename, "r");
    if (!f) { perror("Erreur chargement"); return; }

    char ligne[1024];
    Clef clef_temp;
    int en_creation = 0;

    while (fgets(ligne, sizeof(ligne), f)) {
        if (strncmp(ligne, "id=", 3) == 0) {
            if (en_creation) annuaire[nb_clefs++] = clef_temp;
            init_clef(&clef_temp, ligne+3, "");
            clef_temp.id[strcspn(clef_temp.id, "\n")] = 0;
            en_creation = 1;
        }
        else if (strncmp(ligne, "type=", 5) == 0) {
            strncpy(clef_temp.type, ligne+5, sizeof(clef_temp.type));
            clef_temp.type[strcspn(clef_temp.type, "\n")] = 0;
        }
        else if (strncmp(ligne, "n=", 2) == 0) {
            mpz_set_str(clef_temp.n, ligne+2, 10);
        }
        else if (strncmp(ligne, "e=", 2) == 0) {
            mpz_set_str(clef_temp.e, ligne+2, 10);
        }
        else if (strncmp(ligne, "d=", 2) == 0) {
            mpz_set_str(clef_temp.d, ligne+2, 10);
        }
    }
    if (en_creation) annuaire[nb_clefs++] = clef_temp;
    fclose(f);
    printf("Clés chargées depuis %s.\n", filename);
}

void afficher_clef(Clef *c, const char* quoi) {
    printf("Identifiant: %s (type: %s)\n", c->id, c->type);
    if (strcmp(quoi, "pub") == 0 || strcmp(quoi, "all") == 0) {
        gmp_printf("e: %Zx\nn: %Zx\n", c->e, c->n);
    }
    if (strcmp(quoi, "priv") == 0 || strcmp(quoi, "all") == 0) {
        gmp_printf("d: %Zx\n", c->d);
    }
}
//

void sauvegarder_clefs_contacts(const char* filename) {
    FILE *f = fopen(filename ? filename : "save.txt", "w");
    if (!f) { perror("Erreur sauvegarde"); return; }

    fprintf(f, "=== CLEFS ===\n");
    for (int i = 0; i < nb_clefs; i++) {
        fprintf(f, "id=%s\n", annuaire[i].id);
        fprintf(f, "type=%s\n", annuaire[i].type);
        gmp_fprintf(f, "n=%Zd\n", annuaire[i].n);
        gmp_fprintf(f, "e=%Zd\n", annuaire[i].e);
        gmp_fprintf(f, "d=%Zd\n", annuaire[i].d);
    }

    fprintf(f, "=== CONTACTS ===\n");
    for (int i = 0; i < nb_contacts; i++) {
        fprintf(f, "id=%s\n", annuaire_contacts[i].id);
        fprintf(f, "type=%s\n", annuaire_contacts[i].type);
        fprintf(f, "nom=%s\n", annuaire_contacts[i].nom);
        fprintf(f, "prenom=%s\n", annuaire_contacts[i].prenom);
        fprintf(f, "comment=%s\n", annuaire_contacts[i].comment);
        for (int j = 0; j < annuaire_contacts[i].nb_clefs; j++) {
            fprintf(f, "clef=%s %s\n", annuaire_contacts[i].clefs[j].id, annuaire_contacts[i].clefs[j].type);
        }
    }

    fclose(f);
    printf("Sauvegarde effectuée.\n");
}

void charger_clefs_contacts(const char* filename) {
    FILE *f = fopen(filename ? filename : "save.txt", "r");
    if (!f) { perror("Erreur chargement"); return; }

    char ligne[1024];
    Clef clef_temp;
    Contact contact_temp;
    int en_clef = 0, en_contact = 0;

    while (fgets(ligne, sizeof(ligne), f)) {
        if (strncmp(ligne, "=== CLEFS ===", 13) == 0) {
            en_clef = 1; en_contact = 0;
            continue;
        }
        if (strncmp(ligne, "=== CONTACTS ===", 16) == 0) {
            en_clef = 0; en_contact = 1;
            continue;
        }

        if (en_clef) {
            if (strncmp(ligne, "id=", 3) == 0) {
                init_clef(&clef_temp, ligne+3, "");
                clef_temp.id[strcspn(clef_temp.id, "\n")] = 0;
            } else if (strncmp(ligne, "type=", 5) == 0) {
                strncpy(clef_temp.type, ligne+5, sizeof(clef_temp.type));
                clef_temp.type[strcspn(clef_temp.type, "\n")] = 0;
            } else if (strncmp(ligne, "n=", 2) == 0) {
                mpz_set_str(clef_temp.n, ligne+2, 10);
            } else if (strncmp(ligne, "e=", 2) == 0) {
                mpz_set_str(clef_temp.e, ligne+2, 10);
            } else if (strncmp(ligne, "d=", 2) == 0) {
                mpz_set_str(clef_temp.d, ligne+2, 10);
                annuaire[nb_clefs++] = clef_temp;
            }
        }

        if (en_contact) {
            if (strncmp(ligne, "id=", 3) == 0) {
                init_contact(&contact_temp, ligne+3);
                contact_temp.id[strcspn(contact_temp.id, "\n")] = 0;
            } else if (strncmp(ligne, "type=", 5) == 0) {
                strncpy(contact_temp.type, ligne+5, sizeof(contact_temp.type));
                contact_temp.type[strcspn(contact_temp.type, "\n")] = 0;
            } else if (strncmp(ligne, "nom=", 4) == 0) {
                strncpy(contact_temp.nom, ligne+4, sizeof(contact_temp.nom));
                contact_temp.nom[strcspn(contact_temp.nom, "\n")] = 0;
            } else if (strncmp(ligne, "prenom=", 7) == 0) {
                strncpy(contact_temp.prenom, ligne+7, sizeof(contact_temp.prenom));
                contact_temp.prenom[strcspn(contact_temp.prenom, "\n")] = 0;
            } else if (strncmp(ligne, "comment=", 8) == 0) {
                strncpy(contact_temp.comment, ligne+8, sizeof(contact_temp.comment));
                contact_temp.comment[strcspn(contact_temp.comment, "\n")] = 0;
            } else if (strncmp(ligne, "clef=", 5) == 0) {
                char* val = ligne+5;
                val[strcspn(val, "\n")] = 0;
                char* space = strchr(val, ' ');
                if (space) {
                    *space = 0;
                    strncpy(contact_temp.clefs[contact_temp.nb_clefs].id, val, 100);
                    strncpy(contact_temp.clefs[contact_temp.nb_clefs].type, space+1, 10);
                    mpz_inits(contact_temp.clefs[contact_temp.nb_clefs].n, contact_temp.clefs[contact_temp.nb_clefs].e, NULL);
                    contact_temp.nb_clefs++;
                }
            }
            if (contact_temp.id[0] && contact_temp.nom[0] && contact_temp.prenom[0]) {
                annuaire_contacts[nb_contacts++] = contact_temp;
            }
        }
    }

    fclose(f);
    printf("Chargement effectué.\n");
}



// === Signature ===

void signer_fichier(const char* filein, const char* fileout, Clef* clef) {
    FILE *fin = fopen(filein, "rb");
    FILE *fout = fopen(fileout, "w");
    if (!fin || !fout) { perror("Erreur fichiers"); return; }

    fseek(fin, 0, SEEK_END);
    long taille = ftell(fin);
    rewind(fin);

    unsigned char *buffer = malloc(taille);
    fread(buffer, 1, taille, fin);
    fclose(fin);

    mpz_t message, signature;
    mpz_inits(message, signature, NULL);
    mpz_import(message, taille, 1, 1, 0, 0, buffer);

    rsa_dechiffrer_bloc(signature, message, clef->d, clef->n);

    size_t size;
    uint8_t *bin = (uint8_t *) mpz_export(NULL, &size, 1, 1, 0, 0, signature);

    char* base64_encoded = convert_binary_to_base64(bin, size);
    fprintf(fout, "%s\n", base64_encoded);

    free(buffer);
    free(bin);
    free(base64_encoded);
    mpz_clears(message, signature, NULL);
    fclose(fout);
    printf("Signature écrite dans %s.\n", fileout);
}

void verifier_signature(const char* fileoriginal, const char* filesign, Clef* clef) {
    FILE *fori = fopen(fileoriginal, "rb");
    FILE *fsig = fopen(filesign, "r");
    if (!fori || !fsig) { perror("Erreur fichiers"); return; }

    fseek(fori, 0, SEEK_END);
    long taille_ori = ftell(fori);
    rewind(fori);

    unsigned char *buffer_ori = malloc(taille_ori);
    fread(buffer_ori, 1, taille_ori, fori);
    fclose(fori);

    fseek(fsig, 0, SEEK_END);
    long taille_sig = ftell(fsig);
    rewind(fsig);

    char *buffer_sig = malloc(taille_sig + 1);
    fread(buffer_sig, 1, taille_sig, fsig);
    buffer_sig[taille_sig] = '\0';
    fclose(fsig);

    size_t decoded_size;
    unsigned char *decoded = convert_base64_to_binary(buffer_sig, &decoded_size);
    free(buffer_sig);

    mpz_t original, signature, verif;
    mpz_inits(original, signature, verif, NULL);
    mpz_import(original, taille_ori, 1, 1, 0, 0, buffer_ori);
    mpz_import(signature, decoded_size, 1, 1, 0, 0, decoded);

    rsa_chiffrer_bloc(verif, signature, clef->e, clef->n);

    if (mpz_cmp(original, verif) == 0)
        printf("Signature VALIDE.\n");
    else
        printf("Signature INVALIDE.\n");

    free(buffer_ori);
    free(decoded);
    mpz_clears(original, signature, verif, NULL);
}


// === Certificat ===

void generer_certificat(const char* id, const char* action) {
    Clef* c = chercher_clef(id);
    if (!c) {
        printf("Clef non trouvée.\n");
        return;
    }

    char filename[150];
    snprintf(filename, sizeof(filename), "%s_%s_request.txt", id, action);

    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("Erreur création certificat");
        return;
    }

    fprintf(f, "ID=%s\n", id);
    fprintf(f, "Type=%s\n", c->type);
    gmp_fprintf(f, "n=%Zd\n", c->n);
    gmp_fprintf(f, "e=%Zd\n", c->e);
    fclose(f);

    printf("Demande '%s' générée dans %s.\n", action, filename);
}


// === Contacts ===

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

//############################################################################################################################################################
// === Interpréteur ===
//############################################################################################################################################################

void interpreteur() {
    char commande[BUFFER_SIZE];

    while (1) {
        printf("RSA >>> ");
        if (!fgets(commande, sizeof(commande), stdin)) break;

        commande[strcspn(commande, "\n")] = 0;
        char *cmd = strtok(commande, " ");
        if (!cmd) continue;

        if (strcmp(cmd, "quit") == 0) {
            printf("Fin.\n");
            break;
        }
        else if (strcmp(cmd, "help") == 0) {
            afficher_aide();
        }
        else if (strcmp(cmd, "bin-2b64") == 0) {
            char* filein = strtok(NULL, " ");
            char* fileout = strtok(NULL, " ");
            if (!filein || !fileout) { printf("Usage: bin-2b64 <filein> <fileout>\n"); continue; }
            fichier_binaire_vers_base64(filein, fileout);
        }
        else if (strcmp(cmd, "b64-2bin") == 0) {
            char* filein = strtok(NULL, " ");
            char* fileout = strtok(NULL, " ");
            if (!filein || !fileout) { printf("Usage: b64-2bin <filein> <fileout>\n"); continue; }
            fichier_base64_vers_binaire(filein, fileout);
        }
        else if (strcmp(cmd, "listkeys") == 0) {
            char* id = strtok(NULL, " ");
            if (id) {
                Clef* c = chercher_clef(id);
                if (c) afficher_clef(c, "all");
                else printf("Clé non trouvée.\n");
            } else {
                for (int i = 0; i < nb_clefs; i++) {
                    printf("%s (%s)\n", annuaire[i].id, annuaire[i].type);
                }
            }
        }
        else if (strcmp(cmd, "show") == 0) {
            char* id = strtok(NULL, " ");
            char* mode = strtok(NULL, " ");
            if (!id) { printf("Usage: show <keyid> [pub|priv]\n"); continue; }
            Clef* c = chercher_clef(id);
            if (c) afficher_clef(c, mode ? mode : "all");
            else printf("Clé non trouvée.\n");
        }
        else if (strcmp(cmd, "save") == 0) {
            char* file = strtok(NULL, " ");
            sauvegarder_clefs_contacts(file);
        }
        else if (strcmp(cmd, "load") == 0) {
            char* file = strtok(NULL, " ");
            charger_clefs_contacts(file);
        }
        else if (strcmp(cmd, "savepub") == 0) {
            char* id = strtok(NULL, " ");
            char* filename = strtok(NULL, " ");
            if (!id || !filename) { printf("Usage: savepub <keyid> <filename>\n"); continue; }
            Clef* c = chercher_clef(id);
            if (!c) { printf("Clé non trouvée.\n"); continue; }
            char* pub_b64 = exporter_cle_publique_base64(c->n, c->e);
            FILE* f = fopen(filename, "w");
            if (!f) { perror("Erreur écriture"); free(pub_b64); continue; }
            fprintf(f, "%s\n", pub_b64);
            fclose(f);
            free(pub_b64);
            printf("Clé publique exportée en Base64.\n");
        }
        else if (strcmp(cmd, "rmkeys") == 0) {
            char* id = strtok(NULL, " ");
            if (!id) { printf("Usage: rmkeys <keyid>\n"); continue; }
            for (int i = 0; i < nb_clefs; i++) {
                if (strcmp(annuaire[i].id, id) == 0) {
                    liberer_clef(&annuaire[i]);
                    annuaire[i] = annuaire[--nb_clefs];
                    printf("Clé supprimée.\n");
                    goto fin_rmkeys;
                }
            }
            for (int i = 0; i < nb_contacts; i++) {
                for (int j = 0; j < annuaire_contacts[i].nb_clefs; j++) {
                    if (strcmp(annuaire_contacts[i].clefs[j].id, id) == 0) {
                        mpz_clears(annuaire_contacts[i].clefs[j].n, annuaire_contacts[i].clefs[j].e, NULL);
                        annuaire_contacts[i].clefs[j] = annuaire_contacts[i].clefs[--annuaire_contacts[i].nb_clefs];
                        printf("Clé contact supprimée.\n");
                        goto fin_rmkeys;
                    }
                }
            }
            printf("Clé introuvable.\n");
        fin_rmkeys: ;
        }
        else if (strcmp(cmd, "newkeys") == 0) {
            char* id = strtok(NULL, " ");
            char* type = strtok(NULL, " ");
            if (!id || !type) { printf("Usage: newkeys <keyid> <type>\n"); continue; }
            if (nb_clefs >= MAX_CLEFS) { printf("Trop de clefs.\n"); continue; }
            init_clef(&annuaire[nb_clefs], id, type);

            rsaKey_t pub, priv;
            genKeysRabin(&pub, &priv, 1000000);

            mpz_set_ui(annuaire[nb_clefs].e, pub.E);
            mpz_set_ui(annuaire[nb_clefs].n, pub.N);
            mpz_set_ui(annuaire[nb_clefs].d, priv.E);

            nb_clefs++;
            printf("Clé '%s' créée.\n", id);
        }
        else if (strcmp(cmd, "crypt") == 0) {
            char* filein = strtok(NULL, " ");
            char* fileout = strtok(NULL, " ");
            char* keyid = strtok(NULL, " ");
            if (!filein || !fileout || !keyid) { printf("Usage: crypt <filein> <fileout> <keyid>\n"); continue; }

            Clef* c = chercher_clef(keyid);
            if (c) rsa_chiffrer_fichier(filein, fileout, c->e, c->n);
            else printf("Clé non trouvée.\n");
        }
        else if (strcmp(cmd, "uncrypt") == 0) {
            char* filein = strtok(NULL, " ");
            char* fileout = strtok(NULL, " ");
            char* keyid = strtok(NULL, " ");
            if (!filein || !fileout || !keyid) { printf("Usage: uncrypt <filein> <fileout> <keyid>\n"); continue; }

            Clef* c = chercher_clef(keyid);
            if (c) rsa_dechiffrer_fichier(filein, fileout, c->d, c->n);
            else printf("Clé non trouvée.\n");
        }
        else if (strcmp(cmd, "signtext") == 0) {
            char* filein = strtok(NULL, " ");
            char* keyid = strtok(NULL, " ");
            char* fileout = strtok(NULL, " ");
            if (!filein || !keyid || !fileout) { printf("Usage: signtext <filein> <keyid> <fileout>\n"); continue; }

            Clef* c = chercher_clef(keyid);
            if (c) signer_fichier(filein, fileout, c);
            else printf("Clé non trouvée.\n");
        }
        else if (strcmp(cmd, "verifysign") == 0) {
            char* filein = strtok(NULL, " ");
            char* filesign = strtok(NULL, " ");
            char* keyid = strtok(NULL, " ");
            if (!filein || !filesign || !keyid) { printf("Usage: verifysign <filein> <filesign> <keyid>\n"); continue; }

            Clef* c = chercher_clef(keyid);
            if (c) verifier_signature(filein, filesign, c);
            else printf("Clé non trouvée.\n");
        }
        else if (strcmp(cmd, "certify") == 0) {
            char* id = strtok(NULL, " ");
            if (!id) { printf("Usage: certify <keyid>\n"); continue; }
            generer_certificat(id, "certify");
        }
        else if (strcmp(cmd, "revoke") == 0) {
            char* id = strtok(NULL, " ");
            if (!id) { printf("Usage: revoke <keyid>\n"); continue; }
            generer_certificat(id, "revoke");
        }
        else if (strcmp(cmd, "addcontact") == 0) {
            char* id = strtok(NULL, " ");
            if (!id) { printf("Usage: addcontact <id>\n"); continue; }
            ajouter_contact(id);
        }
        else if (strcmp(cmd, "listcontacts") == 0) {
            char* id = strtok(NULL, " ");
            char* nom = strtok(NULL, " ");
            lister_contacts(id, nom);
        }
        else if (strcmp(cmd, "modifycontact") == 0) {
            char* id = strtok(NULL, " ");
            if (!id) { printf("Usage: modifycontact <id>\n"); continue; }
            modifier_contact(id);
        }
        else if (strcmp(cmd, "addkeys") == 0) {
            char* id = strtok(NULL, " ");
            if (!id) { printf("Usage: addkeys <id ou nom>\n"); continue; }
            ajouter_cle_contact(id);
        }
        else if (strcmp(cmd, "rmcontact") == 0) {
            char* id = strtok(NULL, " ");
            if (!id) { printf("Usage: rmcontact <id>\n"); continue; }
            supprimer_contact(id);
        }
        else {
            printf("Commande inconnue : %s\n", cmd);
        }
    }
}

int main() {
    printf("--- Interpreteur Phase 3 RSA ---\n");
    afficher_aide();
    interpreteur();
    return 0;
}
