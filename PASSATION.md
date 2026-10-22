# Passation : service de comptes

Le guide principal est dans le dépôt `ave-ios` : **`PASSATION.md`** (état des trois dépôts, décisions produit, pièges). Pour ce service :

- Lancer les tests : `pip install -e '.[dev]' && python3 -m pytest` (77 tests).
- Essai de bout en bout contre le vrai moteur : `pip install websockets fastapi uvicorn && python3 scripts/e2e_engine.py --engine-dir ../african-voice-engine` (12 vérifications ; le moteur doit être sur `main` récent ou une branche avec `DELETE /v1/subjects/{sub}/learning`).
- Configuration, routes, sécurité et **limites honnêtes** : `README.md`. Spécification : `contrat/CONTRAT.md` §6 dans `african-voice-engine`.
- Non éprouvé : Sign in with Apple (jamais contre `appleid.apple.com`), App Attest (chaîne synthétique, pas une vraie attestation), envoi réel des codes (adaptateur webhook générique seulement).
