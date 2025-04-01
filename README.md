# Asymmetric-Cryptography-Cystem-DIYPG
Designed and implemented an asymmetric cryptography system inspired by Gnu Privacy Guard (GPG). Features include key pair generation, encryption/decryption, Base64 conversion, command interpreter, and digital signatures.


Phase 1.0 :
Pour un cryptage RSA en production, les nombres premiers devraient être beaucoup plus grands. Toutefois, avec uint64_t, on est limité par 2^64 - 1, ce qui est insuffisant pour un RSA robuste. C'est pourquoi, pour des tests pédagogiques, MAX_PRIME = 10000 est utilisé pour simplifier et garantir le bon fonctionnement des algorithmes.