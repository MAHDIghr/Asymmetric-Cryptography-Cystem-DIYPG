#include <stdio.h>
#include <gmp.h>
#include "../../../include/clef.h"
#include "../../../include/sign.h"
#include "../../../include/rsa_common_header.h"
#include "../../../include/rsa_tools.h"

extern Clef annuaire[MAX_CLEFS];
extern int nb_clefs;

void test_signature() {
    // Génération des clefs RSA
    rsaKey_t pub_sign, priv_sign;
    rsaKey_t pub_chiffre, priv_chiffre;

    // Générer clés pour signature
    genKeysRabin(&pub_sign, &priv_sign, 1000000);
    // Générer clés pour chiffrement
    genKeysRabin(&pub_chiffre, &priv_chiffre, 1000000);

    // Initialiser clef de signature dans annuaire
    init_clef(&annuaire[nb_clefs], "sign", "sign");
    mpz_set_ui(annuaire[nb_clefs].e, pub_sign.E);
    mpz_set_ui(annuaire[nb_clefs].n, pub_sign.N);
    mpz_set_ui(annuaire[nb_clefs].d, priv_sign.E);
    nb_clefs++;

    // Initialiser clef de chiffrement dans annuaire
    init_clef(&annuaire[nb_clefs], "chiffre", "crypt");
    mpz_set_ui(annuaire[nb_clefs].e, pub_chiffre.E);
    mpz_set_ui(annuaire[nb_clefs].n, pub_chiffre.N);
    mpz_set_ui(annuaire[nb_clefs].d, priv_chiffre.E);  // Nécessaire pour déchiffrement
    nb_clefs++;

    // Fichier à signer
    const char* fichier = "data/input/message.txt";
    const char* signature_file = "signature_test.txt";

    // Signer le fichier : avec clé "sign" (privée) et "chiffre" (publique)
    signer_fichier(fichier, signature_file, "sign", "chiffre");

    // Vérifier la signature
    int valide = verifier_signature(fichier, signature_file, "sign", "chiffre");
    printf("Résultat de la vérification (fichier) : %s\n", valide ? "VALIDÉ" : "INVALIDE");

    // Calcul manuel pour comparer
    Clef* clef_sign = chercher_clef("sign");
    Clef* clef_chiffre = chercher_clef("chiffre");
    if (!clef_sign || !clef_chiffre) {
        printf("Erreur : clés non trouvées.\n");
        return;
    }

    BYTE hash[32];
    if (hash_fichier_sha256(fichier, hash) != 0) {
        printf("Erreur de hachage manuel\n");
        return;
    }

    mpz_t hash_chiffre;
    mpz_init(hash_chiffre);
    chiffrer_hash(hash_chiffre, hash, clef_chiffre);

    mpz_t sig;
    mpz_init(sig);
    signer_hash(sig, (BYTE *)mpz_export(NULL, NULL, 1, 1, 0, 0, hash_chiffre), clef_sign);

    gmp_printf("Signature manuelle (chiffré avant signature) : %Zx\n", sig);

    mpz_clears(sig, hash_chiffre, NULL);

    // Nettoyage
    liberer_clef(clef_sign);
    liberer_clef(clef_chiffre);
    remove(signature_file);
}


int main() {
    test_signature();
    return 0;
}
