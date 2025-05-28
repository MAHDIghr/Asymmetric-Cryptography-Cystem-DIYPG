/// \file sign.c
/// \author Oliver SEARLE
/// \date mai 2025

#include "../../include/sign.h"

int hash_fichier_sha256(const char *chemin_fichier, BYTE hash[32]) {
    /// \brief hash le fichier 
    FILE *fichier = fopen(chemin_fichier, "rb");
    if (!fichier) {
        perror("Erreur à l'ouverture du fichier");
        return -1;
    }

    SHA256_CTX ctx;
    BYTE buffer[BUFFER_SIZE];
    size_t lu;

    sha256_init(&ctx);
    while ((lu = fread(buffer, 1, BUFFER_SIZE, fichier)) > 0) {
        sha256_update(&ctx, buffer, lu);
    }

    sha256_final(&ctx, hash);
    fclose(fichier);
    return 0;
}

void chiffrer_hash(mpz_t chiffré, const BYTE hash[32], Clef* clef_publique) {
    /// \brief Chiffre avec la clé de chiffrement le hash crée.
    mpz_t m;
    mpz_init(m);

    // Convertir le hash en mpz_t
    mpz_import(m, 32, 1, 1, 0, 0, hash);
    if (mpz_cmp(m, clef_publique->n) >= 0) {
        mpz_mod(m, m, clef_publique->n);
    }

    // chiffré = hash^e mod n
    mpz_powm(chiffré, m, clef_publique->e, clef_publique->n);

    mpz_clear(m);
}

void dechiffrer_hash(mpz_t hash_dechiffre, mpz_t hash_chiffre, Clef* clef_privee) {
    /// \brief hash_dechiffre = (hash_chiffre)^d mod n
    mpz_powm(hash_dechiffre, hash_chiffre, clef_privee->d, clef_privee->n);
}

void signer_hash(mpz_t signature, const BYTE hash[32], Clef *clef_privee) {
    /// \brief signer le hash chiffré ou non
    mpz_t m;
    mpz_init(m);

    // Convertir le hash (tableau de 32 octets) en mpz_t
    mpz_import(m, 32, 1, 1, 0, 0, hash);
    if (mpz_cmp(m, clef_privee->n) >= 0) {
        mpz_mod(m, m, clef_privee->n);
    }
    
    // signature = hash^d mod n
    mpz_powm(signature, m, clef_privee->d, clef_privee->n);

    mpz_clear(m);
}

void signer_fichier(const char* filein, const char* fileout, const char* keyid_sign, const char* keyid_chiffre) {
    /// \brief Fonction englobante qui effecte tout les traitements de hashage, chiffrement et signature.
    Clef* clef_signature = chercher_clef(keyid_sign);
    Clef* clef_chiffrement = chercher_clef(keyid_chiffre);

    if (!clef_signature || !clef_chiffrement) {
        printf("Clé de signature ou de chiffrement non trouvée.\n");
        return;
    }

    BYTE hash[32];
    if (hash_fichier_sha256(filein, hash) != 0) {
        printf("Erreur de hachage du fichier.\n");
        return;
    }

    mpz_t hash_chiffre;
    mpz_init(hash_chiffre);
    chiffrer_hash(hash_chiffre, hash, clef_chiffrement);

    mpz_t signature;
    mpz_init(signature);
    // signer le hash chiffré
    mpz_powm(signature, hash_chiffre, clef_signature->d, clef_signature->n);

    FILE* f = fopen(fileout, "w");
    if (!f) {
        perror("Erreur écriture signature");
        mpz_clears(signature, hash_chiffre, NULL);
        return;
    }

    // Écriture : signature + hash chiffré
    gmp_fprintf(f, "%Zx\n", signature);
    gmp_fprintf(f, "%Zx\n", hash_chiffre);  // facultatif, utile pour vérif
    fclose(f);

    mpz_clears(signature, hash_chiffre, NULL);
    printf("Signature enregistrée dans %s\n", fileout);
}

int verifier_signature(const char* filein, const char* filesign, const char* keyid_sign, const char* keyid_crypt) {
    /// \brief compare le fichier filein hashé avec filesign après déchiffrement
    Clef* clef_verif = chercher_clef(keyid_sign);
    Clef* clef_dechiffre = chercher_clef(keyid_crypt);

    if (!clef_verif || !clef_dechiffre) {
        printf("Clé publique ou clé de déchiffrement non trouvée.\n");
        return 0;
    }

    BYTE hash_attendu[32];
    if (hash_fichier_sha256(filein, hash_attendu) != 0) {
        printf("Erreur de hachage du fichier pour vérification.\n");
        return 0;
    }

    // Lire la signature et le hash chiffré
    mpz_t signature, hash_chiffre;
    mpz_inits(signature, hash_chiffre, NULL);
    FILE* fsig = fopen(filesign, "r");
    if (!fsig) {
        perror("Erreur ouverture signature");
        mpz_clears(signature, hash_chiffre, NULL);
        return 0;
    }
    if (gmp_fscanf(fsig, "%Zx\n%Zx", signature, hash_chiffre) != 2) {
        printf("Erreur de lecture de la signature ou du hash chiffré.\n");
        fclose(fsig);
        mpz_clears(signature, hash_chiffre, NULL);
        return 0;
    }
    fclose(fsig);

    // Recalculer hash signé : s^e mod n
    mpz_t hash_calcule;
    mpz_init(hash_calcule);
    mpz_powm(hash_calcule, signature, clef_verif->e, clef_verif->n);

    // Déchiffrer le hash
    mpz_t hash_dechiffre;
    mpz_init(hash_dechiffre);
    dechiffrer_hash(hash_dechiffre, hash_calcule, clef_dechiffre);

    // Convertir le hash attendu pour comparaison
    mpz_t m_attendu;
    mpz_init(m_attendu);
    mpz_import(m_attendu, 32, 1, 1, 0, 0, hash_attendu);
    if (mpz_cmp(m_attendu, clef_dechiffre->n) >= 0) {
        mpz_mod(m_attendu, m_attendu, clef_dechiffre->n);
    }

    int valide = (mpz_cmp(m_attendu, hash_dechiffre) == 0);

    printf("Hash attendu   : ");
    gmp_printf("%Zx\n", m_attendu);
    printf("Hash déchiffré : ");
    gmp_printf("%Zx\n", hash_dechiffre);

    mpz_clears(signature, hash_chiffre, hash_calcule, hash_dechiffre, m_attendu, NULL);
    return valide;
}
