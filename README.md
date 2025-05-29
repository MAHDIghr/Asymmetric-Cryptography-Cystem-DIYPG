**Membres de l’équipe 04 :**
- Searle Oliver
- Chenouf Malaq
- Gherbi Kamel Mahdi 

# DIYPG – Do It Yourself Privacy Guard

## 1. Introduction
Ce projet implémente un système de chiffrement et de signature inspiré de GnuPG, fondé sur l’algorithme RSA. Le développement se fait en cinq phases pour couvrir progressivement les briques essentielles :

- **Phase 1** : théorie des nombres, tests de primalité, chiffrement octet par octet, conversion Base64.
- **Phase 2** : chiffrement par blocs (4 octets) avec multiprécision (GMP), import/export binaire et Base64.
- **Phase 3** : interpréteur de commandes interactif, annuaire de clés et de contacts.
- **Phase 4** : signatures SHA-256 + RSA et vérification d’intégrité.
- **Phase 5** : gestion de clés via une blockchain simplifiée en Python.

Chaque phase dispose de son propre sous-dossier dans `src/`, d’un Makefile global, et de suites de tests unitaires, fonctionnels et d’intégration dans `tests/`.

## 2. Prérequis
- **Langages** : C (phases 1–4), Python  (phase 5).
- **Bibliothèques** : GMP (phase 2), OpenSSL ou implémentation interne pour SHA-256 (phase 4).
- **Outils** : GNU Make, gcc, pip (pour la phase 5).



 ## 3. Organisation du dépôt
```
/include/        # En-têtes communs et spécifiques
/src/
  core/          # Modules d’arithmétique et utilitaires
  phase1/        # Implémentation de la théorie des nombres + Base64
  phase2/        # Chiffrement par blocs et import/export GMP
  interprete/        # Interpréteur CLI et annuaire de clés/contacts
  phase4/        # Fonctions de signature et vérification
  phase5/        # Blockchain Python pour la gestion de clés
/tests/          # Tests unitaires, fonctionnels et d’intégration
/bin/            # Exécutables générés (main, interprete, tests)
/Makefile        # Compilation globale et gestion des tests
/README.md       # Documentation du projet
```
## 4. Installation & Compilation
Cloner le dépôt puis compiler l’ensemble :
```bash
git clone https://github.com/MAHDIghr/Asymmetric-Cryptography-Cystem-DIYPG.git
cd <projet>
make 
```

Tous les exécutables (y compris main, interprete et les tests) seront disponibles dans bin/.

## 5. Utilisation

### 5.1 Phase 1 – RSA basique & Base64

Phase 1.0 :
Pour un cryptage RSA en production, les nombres premiers devraient être beaucoup plus grands. Toutefois, avec uint64_t, on est limité par 2^64 - 1, ce qui est insuffisant pour un RSA robuste. C'est pourquoi, pour des tests pédagogiques, MAX_PRIME = 10000 est utilisé pour simplifier et garantir le bon fonctionnement des algorithmes.

1. Fonctions d'affichage des clés dans un format lisible
   - La fonction `printKey()` affiche une clé RSA (exposant et modulo).
   - La fonction `printKeyPair()` affiche la paire de clés (publique et privée).

2. Fichiers de test
   - Le fichier `test_keys.c` génère une paire de clés RSA à l'aide de `genKeysRabin()` et affiche les résultats via `printKeyPair()`.
   - Ces tests permettent de vérifier le bon fonctionnement des fonctions de génération et d'affichage.

4. Paramétrage de MAX_PRIME
   - La constante `MAX_PRIME` est définie dans le fichier `rsa_header.h`
 à la valeur 10000.
   - Cette valeur peut être modifiée pour explorer les limites de la capacité des uint64_t et observer les dépassements éventuels.

-----
- **Valeur de MAX_PRIME** : Pour les tests, MAX_PRIME est initialement fixée à 10000. Cela garantit que les opérations restent dans les limites d'un uint64_t sans nécessiter l'utilisation de bibliothèques comme GMP.
- **Exhaustivité des tests** : Les tests réalisés via `test_keys.c` couvrent la génération de clés RSA ainsi que l'affichage lisible des résultats. D'autres tests unitaires peuvent être ajoutés pour vérifier individuellement chaque fonction (primalité, décomposition, exponentiation modulaire, etc.).


### 5.2 Phase 2 – chiffrement par blocs (GMP)
Traite les fichiers 4 octets à la fois en utilisant GMP pour les opérations modulo.

```bash
# Générer une paire de clés (1024 bits)
./bin/main genkey --phase 2 --bits 1024 --out pub.key priv.key
# Chiffrer un fichier
./bin/main encrypt --phase 2 --input message.txt --output message.enc --pubkey pub.key
# Déchiffrer un fichier
./bin/main decrypt --phase 2 --input message.enc --output message_dec.txt --privkey priv.key
# Export Base64 d’une clé publique
./bin/main savepub pub.key pub_b64.txt
# Conversion binaire ↔ Base64
./bin/main bin-2b64 message.enc message.b64
./bin/main b64-2bin message.b64 message2.enc
```

### Phase 3 – CLI & annuaire (bin/interprete)

Cette phase fournit un shell interactif (`bin/interprete`) pour gérer vos clés RSA et vos contacts, sans passer par des arguments en ligne de commande à chaque fois.

#### Commandes principales

```
newkeys <id> <type>       # créer clé
listkeys [id] [pub|priv]  # lister
rmkeys <id>               # supprimer
crypt <in> <out> <id>     # chiffrer fichier
uncrypt <in> <out> <id>   # déchiffrer
bin-2b64 <in> <out>       # Base64
b64-2bin <in> <out>
signtext <in> <out> <s> <c>    # hach+chiffr+sign
verifysign <in> <sig> <s> <c>  # vérif signature
save [file] <id>          # sauvegarde cryptée
load [file] <id>          # chargement crypté
savepub <id> <file>       # clé pub Base64
addcontact <id>           # ajouter contact
listcontacts [id][nom]    # lister contacts
modifycontact <id>        # modifier commentaire
addkeys <id/nom>          # ajouter clé contact
rmcontact <id>            # supprimer contact
certify/revoke <id>       # demande certif/révoc
quit                      # quitter
```
### 5.4 Phase 4 – Signatures SHA-256 + RSA

Cette phase ajoute la possibilité de signer et de vérifier l’intégrité des fichiers en combinant un hachage SHA-256 et une clé RSA.

#### Fonctions principales
- `hash_fichier_sha256` : calcule le digest 32 octets d’un fichier  
- `signer_hash` / `chiffrer_hash` : conversion du hash en mpz_t et chiffrement  
- `signer_fichier` : hache, chiffre (optionnel) et signe le hash pour produire un fichier `.sig`  
- `verifier_signature` : déchiffre la signature, recalcule le hash et compare

#### Exemples CLI (via `main`)
```bash
# Signer un document
./bin/main sign \
  --input document.txt \
  --output document.sig \
  --keysign priv.key \
  --keycrypt pub.key

# Vérifier une signature
./bin/main verify \
  --input document.txt \
  --sig document.sig \
  --keysign pub.key \
  --keycrypt priv.key
```
### 5.5 Phase 5 –Gestion décentralisée des clés via Blockchain

---

# 1. Installation

1. **Cloner le dépôt**

   ```bash
   git clone https://github.com/satwikkansal/python_blockchain_app.git
   cd python_blockchain_app
   ```
2. **Créer et activer un environnement virtuel**

   ```bash
   python -m venv venv
   # Windows PowerShell
   .\venv\Scripts\Activate.ps1
   ```
3. **Installer les dépendances**

   ```bash
   pip install -r requirements.txt pycryptodome flask requests
   ```

---

## 2. Lancement des serveurs

* **API REST (back‑end)** – écoute sur le port 8000 :

  ```bash
  (venv) $ python node_server.py
  ```
* **Interface web (front‑end)** – écoute sur le port 5000 (optionnel) :

  ```bash
  (venv) $ python run_app.py
  ```

---

## 3. Génération de la paire de clés RSA

Exécuter :

```bash
(venv) $ openssl genrsa  -out private_key.pem 2048
(venv) $ openssl rsa     -in private_key.pem -pubout -out public_key.pem
```

---

## 4. Script de création et signature de transactions (`tx.py`)

Ce script génère un fichier JSON signé pour l’un des événements :

* `NCK` : nouvelle clé publique
* `RCK` : révocation de clé publique
* `NSK` : nouvelle clé de signature
* `RSK` : révocation de clé de signature

```python
#!/usr/bin/env python3
import sys, json, base64, time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# 1) Vérifier l'argument
events = ("NCK","RCK","NSK","RSK")
if len(sys.argv)!=2 or sys.argv[1] not in events:
    print("Usage: python tx.py <event: NCK|RCK|NSK|RSK>")
    sys.exit(1)

event = sys.argv[1]

# 2) Charger les clés
with open('private_key.pem','rb') as f:
    priv = RSA.import_key(f.read())
with open('public_key.pem','r') as f:
    pub_str = f.read()

# 3) Construire la transaction
tx = {
  "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
  "event":     event,
  "key":       pub_str,
  "identity":  {
      "email":      "email@domaine.com",
      "public_key": pub_str
  }
}

# 4) Signer
data = json.dumps(tx, separators=(',',':')).encode()
h   = SHA256.new(data)
sig = pkcs1_15.new(priv).sign(h)
tx["signature"] = base64.b64encode(sig).decode()

# 5) Sauvegarder
filename = f"signed_{event}.json"
with open(filename,'w') as f:
    json.dump(tx, f, indent=2)
print(f"✅ {filename} créé")
```

> **Important** : remplacez votre adresse email dans le champ `identity.email`.

---

## 5. Exécution d’un événement

Pour chaque type d’événement (`NCK`, `RCK`, `NSK`, `RSK`), suivez ce workflow :

1. **Générer le JSON signé**

   ```bash
   (venv) $ python tx.py NCK
   # crée "signed_NCK.json"
   ```
2. **Poster la transaction**

   ```bash
   (venv) $ curl.exe -X POST http://127.0.0.1:8000/new_transaction \
     -H "Content-Type: application/json" \
     --data-binary "@signed_NCK.json"
   ```
3. **Miner le bloc**

   ```bash
   (venv) $ curl.exe http://127.0.0.1:8000/mine
   ```
4. **Vérifier la chaîne**

   ```bash
   (venv) $ curl.exe http://127.0.0.1:8000/chain
   ```

Répétez ces quatre étapes pour `NCK`, `RCK`, `NSK` et enfin `RSK`.

---

## 6. Résultat attendu

Après avoir traité les quatre événements dans l’ordre, la commande `/chain` renvoie une blockchain de longueur 5 : genesis + 4 blocs contenant chacun l’événement correspondant.

Extrait :

```json
{
  "length": 5,
  "chain": [
    {"index":0,...},
    {"index":1,"transactions":[{"event":"NCK"}],...},
    {"index":2,"transactions":[{"event":"RCK"}],...},
    {"index":3,"transactions":[{"event":"NSK"}],...},
    {"index":4,"transactions":[{"event":"RSK"}],...}
  ],
  "peers": []
}
```

---

## 7. Retour d’expérience

* Le script `tx.py` rend la création des transactions uniforme.
* La séparation back‑end / front‑end facilite les tests et l’interface utilisateur.
* Le proof‑of‑work garantit l’intégrité et l’immuabilité des blocs.

---

