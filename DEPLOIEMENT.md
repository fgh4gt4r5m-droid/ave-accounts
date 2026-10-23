# Déployer le service de comptes sur Render (pas à pas)

Rédigé le 2026-10-23. Même compte Render que WoYo (`taksi-backend`), mais un **service séparé** : rien n'est modifié côté
WoYo. **Aucun secret ne s'écrit dans ce dépôt ni dans une conversation** : on les colle directement dans Render.

## 0. Prérequis (bloquants)
1. **Le moteur AVE est déployé** à une adresse `https://…` (WebSocket `wss://…/v1/stream`). En production, ce service
   **refuse de démarrer** sans lui : c'est le moteur qui délivre les jetons courts. Il relève de l'autre session.
2. **La clé du tenant « AVE grand public »**, générée avec l'outil du moteur :
   `python3 tools/make_key.py ave-grand-public customer_service --langs fra --learning opt_in`
   (à coller dans Render, jamais ailleurs).
3. **Au moins un moyen d'envoyer les codes** (WhatsApp, Orange ou Infobip, voir §3). Sinon : le service refuse de démarrer.

## 1. Créer le service
1. Render → **New → Blueprint** → dépôt `fgh4gt4r5m-droid/ave-accounts` (accorder l'accès à Render s'il le demande).
2. Render lit `render.yaml` : service web **ave-accounts** (Docker, offre Starter, région Frankfurt), disque de 1 Go monté
   sur `/data` pour la base. Il demande les valeurs marquées secrètes (§2 et §3).
3. Adresse obtenue : `https://ave-accounts.onrender.com` (ou proche ; Render l'affiche). Un vrai domaine viendra plus tard.

## 2. Valeurs à saisir dans Render (Environment)
| Variable | Valeur |
|---|---|
| `ACCOUNTS_SECRET` | 64 caractères aléatoires. Sur Windows (PowerShell) : `[Convert]::ToBase64String((1..48 \| % { Get-Random -Max 256 }) -as [byte[]])`. **À garder** : le perdre ou le changer rompt tous les comptes. |
| `ACCOUNTS_ENGINE_URL` | `https://…` du moteur |
| `ACCOUNTS_ENGINE_KEY` | clé du tenant (prérequis 2) |
| `ACCOUNTS_APPLE_AUDIENCE` | déjà réglé : `com.tam.ave` |

Mode invité (App Attest), facultatif au départ : `ACCOUNTS_APPATTEST_APP_ID=<TEAM_ID>.com.tam.ave` et un **Secret File**
Render nommé `apple_appattest_root.pem` (racine publique « Apple App Attestation Root CA », téléchargée chez Apple), puis
`ACCOUNTS_APPATTEST_ROOT_PEM=/etc/secrets/apple_appattest_root.pem`. Sans eux, « Essayer sans compte » répond « non disponible ».

## 3. Envoi des codes (WhatsApp, puis SMS Orange, puis SMS Infobip)
Ordre : canal WhatsApp choisi dans l'app → WhatsApp, et en cas d'échec les SMS ; canal SMS → Orange puis Infobip
(`ACCOUNTS_SMS_PROVIDERS`). Un fournisseur non configuré est simplement sauté.

- **WhatsApp (Meta Cloud API)** — mêmes comptes Meta que WoYo :
  - Business Manager → WhatsApp → Modèles : créer un modèle **Authentification**, nom **`ave_otp`**, langue **Français**,
    bouton **« Copier le code »** ; attendre l'approbation de Meta.
  - `ACCOUNTS_WHATSAPP_TOKEN` (jeton permanent d'un utilisateur système) et `ACCOUNTS_WHATSAPP_PHONE_NUMBER_ID`.
  - ⚠️ Le message part du compte WhatsApp Business existant : il s'affichera sous le nom **WOYO** tant qu'AVE n'a pas son
    propre numéro WhatsApp Business.
- **SMS Orange** (Orange Developer, API « SMS » Afrique) : `ACCOUNTS_ORANGE_CLIENT_ID`, `ACCOUNTS_ORANGE_CLIENT_SECRET`
  (MyApps) ; expéditeur Guinée `2240000` par défaut ; `ACCOUNTS_ORANGE_SENDER_NAME` seulement si Orange a validé un nom
  (11 caractères max). Le contrat doit avoir un solde positif.
- **SMS Infobip** (repli, comme WoYo) : `ACCOUNTS_INFOBIP_BASE_URL` (`https://xxxxx.api.infobip.com`, portail Infobip),
  `ACCOUNTS_INFOBIP_API_KEY` (droit `sms:message:send`), `ACCOUNTS_INFOBIP_SENDER` (défaut `AVE`).

## 4. Numéro de démonstration pour la revue Apple
`ACCOUNTS_OTP_TEST_PHONES=+224…` (un ou plusieurs, séparés par des virgules) et `ACCOUNTS_OTP_TEST_CODE` = 6 chiffres
**non évidents** (000000, 123456… sont refusés). Ces numéros ne reçoivent aucun message ; le code fixe est donné à Apple
dans « Informations pour la revue ». Les retirer si inutiles.

## 5. Vérifier
- Render → Logs : démarrage sans `ConfigError`.
- Navigateur : `https://ave-accounts.onrender.com/healthz` répond.
- Puis Codemagic → groupe de variables **`ave`** : `AVE_ACCOUNTS_URL=https://ave-accounts.onrender.com` et
  `AVE_ENDPOINT=wss://…/v1/stream` (moteur), et lancer `ave-testflight`.

## Ce qui n'est PAS éprouvé (honnêteté)
- Les trois envois suivent la documentation publique de Meta, Orange et Infobip et sont testés contre des faux ; **aucun
  n'a encore été appelé pour de vrai**. Premier essai : sur un numéro de l'équipe, en regardant les journaux Render.
- Le format exact du bouton « Copier le code » de Meta varie selon les sources : à confirmer au premier envoi réel.
- Image Docker non construite ici (pas de Docker sur le poste) : Render la construira au premier déploiement.
- Sauvegarde de la base SQLite : non faite (disque Render seulement). À prévoir avant d'avoir de vrais utilisateurs.
