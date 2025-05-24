# Asymmetric-Cryptography-Cystem-DIYPG
Designed and implemented an asymmetric cryptography system inspired by Gnu Privacy Guard (GPG). Features include key pair generation, encryption/decryption, Base64 conversion, command interpreter, and digital signatures.


Phase 1.0 :
Pour un cryptage RSA en production, les nombres premiers devraient être beaucoup plus grands. Toutefois, avec uint64_t, on est limité par 2^64 - 1, ce qui est insuffisant pour un RSA robuste. C'est pourquoi, pour des tests pédagogiques, MAX_PRIME = 10000 est utilisé pour simplifier et garantir le bon fonctionnement des algorithmes.


Projet RSA – Phase 1.0
======================

Ce livrable contient l'implémentation de la phase 1.0 du projet RSA, comprenant :

1. Fonctions d'affichage des clés dans un format lisible
   - La fonction `printKey()` affiche une clé RSA (exposant et modulo).
   - La fonction `printKeyPair()` affiche la paire de clés (publique et privée).

2. Fichiers de test
   - Le fichier `test_keys.c` génère une paire de clés RSA à l'aide de `genKeysRabin()` et affiche les résultats via `printKeyPair()`.
   - Ces tests permettent de vérifier le bon fonctionnement des fonctions de génération et d'affichage.

4. Paramétrage de MAX_PRIME
   - La constante `MAX_PRIME` est définie dans le fichier `rsa_header.h` à la valeur 10000.
   - Cette valeur peut être modifiée pour explorer les limites de la capacité des uint64_t et observer les dépassements éventuels.

Bilan
-----
- **Valeur de MAX_PRIME** : Pour les tests, MAX_PRIME est initialement fixée à 10000. Cela garantit que les opérations restent dans les limites d'un uint64_t sans nécessiter l'utilisation de bibliothèques comme GMP.
- **Exhaustivité des tests** : Les tests réalisés via `test_keys.c` couvrent la génération de clés RSA ainsi que l'affichage lisible des résultats. D'autres tests unitaires peuvent être ajoutés pour vérifier individuellement chaque fonction (primalité, décomposition, exponentiation modulaire, etc.).

Ce livrable permet de valider la phase 1.0 du projet, en mettant en œuvre la génération des clés RSA et en fournissant un affichage clair pour faciliter le débogage et la vérification des résultats.
