**Membres de l’équipe 04 :**
- Searle Oliver
- Chenouf Malaq
- Gherbi Kamel Mahdi 

# Compilation
- make all
- ./bin/interprete


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
   - La constante `MAX_PRIME` est définie dans le fichier `rsa_header.h`
 à la valeur 10000.
   - Cette valeur peut être modifiée pour explorer les limites de la capacité des uint64_t et observer les dépassements éventuels.

Bilan
-----
- **Valeur de MAX_PRIME** : Pour les tests, MAX_PRIME est initialement fixée à 10000. Cela garantit que les opérations restent dans les limites d'un uint64_t sans nécessiter l'utilisation de bibliothèques comme GMP.
- **Exhaustivité des tests** : Les tests réalisés via `test_keys.c` couvrent la génération de clés RSA ainsi que l'affichage lisible des résultats. D'autres tests unitaires peuvent être ajoutés pour vérifier individuellement chaque fonction (primalité, décomposition, exponentiation modulaire, etc.).




======================
# Phase 5 –Gestion décentralisée des clés via Blockchain

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

