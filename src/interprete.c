/// \file interprete.c
/// \author Oliver SEARLE
/// \date avril 2025

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "../include/rsa_tools.h"
#include "../include/rsa_common_header.h"
#include "../include/phase2.h"
#include "../include/contact.h"
#include "../include/clef.h"
#include "../include/sign.h"


#define BUFFER_SIZE 512

// === Aide ===

void afficher_aide() {
    printf("\nCommandes disponibles :\n");
    printf("  newkeys <keyid> <type>\n");
    printf("  listkeys [keyid] [pub|priv]\n");
    printf("  rmkeys <keyid>\n");
    printf("  crypt <filein> <fileout> <keyid>\n");
    printf("  uncrypt <filein> <fileout> <keyid>\n");
    printf("  signtext <filein> <fileout> <keysign> <keycrypt> \n");
    printf("  verifysign <filein> <filsig> <keysign> <keycrypt> \n");
    printf("  save [filename] <keyid> \n");
    printf("  load [filename] <keyid>\n");
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


void sauvegarder_clefs_contacts(const char* filename) {
    /// \brief Sauvegarde dans un fichier (filename ou save.txt par defaut) toutes les clefs et tout les contacts. 
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

void sauvegarder_clefs_contacts_secure(const char* filename, Clef* clef_crypt) {
    const char* temp = "temp.txt";
    const char* final_file = filename ? filename : "save.enc";

    // Sauvegarder en clair dans un fichier temporaire
    sauvegarder_clefs_contacts(temp);

    // Chiffrer avec RSA
    rsa_chiffrer_fichier(temp, final_file, clef_crypt->e, clef_crypt->n);

    remove(temp);

    printf("Fichier sécurisé sauvegardé dans %s\n", final_file);
}

void charger_clefs_contacts(const char* filename) {
    /// \brief Charge du fichier (filename ou save.txt par defaut) toutes les clefs et les contacts.
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

void charger_clefs_contacts_secure(const char* filename, Clef* clef_crypt) {
    const char* temp = "temp.txt";
    const char* source = filename ? filename : "save.enc";

    // Déchiffrer dans un fichier temporaire
    rsa_dechiffrer_fichier(source, temp, clef_crypt->d, clef_crypt->n);

    // Charger les données comme avant
    charger_clefs_contacts(temp);

    remove(temp);

    printf("Fichier sécurisé chargé depuis %s\n", source);
}

// === Certificat ===

void generer_certificat(const char* id, const char* action) {
    /// \brief Crée un fichier x_x_request.txt avec une demande à l'autorité de certification.
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
            for (int i = 0; i < nb_clefs; i++) {
                printf("%s (%s)\n", annuaire[i].id, annuaire[i].type);
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
            char* keyid = strtok(NULL, " ");
            Clef* c = chercher_clef(keyid);
            if (!c) { printf("Clé de chiffrement non trouvée.\n"); continue; }
            sauvegarder_clefs_contacts_secure(file, c);
        }
        
        else if (strcmp(cmd, "load") == 0) {
            char* file = strtok(NULL, " ");
            char* keyid = strtok(NULL, " ");
            Clef* c = chercher_clef(keyid);
            if (!c) { printf("Clé de déchiffrement non trouvée.\n"); continue; }
            charger_clefs_contacts_secure(file, c);
        }
        else if (strcmp(cmd, "savepub") == 0) {
            char* id = strtok(NULL, " ");
            char* filename = strtok(NULL, " ");
            if (!id || !filename) { printf("Usage: savepub <keyid> <filename>\n"); continue; }

            Clef* c = chercher_clef(id);
            if (!c) { printf("Clé non trouvée.\n"); continue; }
            // Convetit la clef publique en base64
            char* pub_b64 = exporter_cle_publique_base64(c->n, c->e);
            FILE* f = fopen(filename, "w");
            if (!f) { perror("Erreur écriture"); free(pub_b64); continue; }
            // écrit la clef convertie dans le fichier
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
                    // regarde les clefs de tout les contacts
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
            char* fileout = strtok(NULL, " ");
            char* keysign = strtok(NULL, " ");
            char* keycrypt = strtok(NULL, " ");
            if (!filein || !fileout || !keysign || !keycrypt){
                printf("Usage: signtext <filein> <fileout> <keysign> <keycrypt>\n");
                continue;
            }
            signer_fichier(filein, fileout,keysign,keycrypt);
        }        
        else if (strcmp(cmd, "verifysign") == 0) {
            char* filein = strtok(NULL, " ");
            char* filesign = strtok(NULL, " ");
            char* keysign = strtok(NULL, " ");
            char* keycrypt = strtok(NULL, " ");
            if (!filein || !filesign || !keysign || !keycrypt) {
                printf("Usage: verifysign <filein> <filesign> <keysign> <keycrypt>\n");
                continue;
            }
        
            int valid = verifier_signature(filein, filesign, keysign,keycrypt);
            if (valid)
                printf("Signature VALIDE.\n");
            else
                printf("Signature INVALIDE.\n");
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
    printf("--- Interpréteur RSA Phase 3 ---\n");
    afficher_aide();
    interpreteur();
    return 0;
}

