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

**Sign in with Apple — révocation (obligatoire si Apple est activé, exigé par l'App Store)** :
1. developer.apple.com → Certificates, IDs & Profiles → **Keys** → « + » → nom `AVE Sign in with Apple` → cocher
   **Sign in with Apple** → Configure → Primary App ID `com.tam.ave` → Save → Continue → Register.
2. **Télécharger le fichier .p8** (une seule fois possible) et noter le **Key ID** ; l'identifiant d'équipe (Team ID) est en
   haut à droite du portail.
3. Render → ave-accounts → Environment → **Secret Files** → nom `apple_signin_key.p8`, contenu = le fichier .p8 ;
   variables `ACCOUNTS_APPLE_TEAM_ID` et `ACCOUNTS_APPLE_KEY_ID`. Le chemin est déjà réglé (`/etc/secrets/apple_signin_key.p8`).
Sans ces trois valeurs, le service refuse de démarrer en production tant que Sign in with Apple est activé.

Mode invité (App Attest), facultatif au départ : `ACCOUNTS_APPATTEST_APP_ID=<TEAM_ID>.com.tam.ave` et un **Secret File**
Render nommé `apple_appattest_root.pem` (racine publique « Apple App Attestation Root CA », téléchargée chez Apple), puis
`ACCOUNTS_APPATTEST_ROOT_PEM=/etc/secrets/apple_appattest_root.pem`. Sans eux, « Essayer sans compte » répond « non disponible ».

## 3. Envoi des codes : les mêmes fournisseurs que taksi-backend (vérifié le 2026-10-23)
Copie de la logique de `taksi-backend` (`src/auth/auth.service.ts`, `main` du 2026-10-23), éprouvée en production chez TAM :
canal WhatsApp → WhatsApp, puis SMS ; SMS → **Orange Guinée** pour un numéro `+224` (100 à 200 GNF, tous opérateurs, 3 SMS
par jour au plus au même numéro), puis **Infobip** (`/sms/2/text/advanced`) ; un numéro étranger saute Orange.
Les valeurs sont celles déjà posées sur le service Render de taksi-backend : les recopier dans le service `ave-accounts`
(Render → taksi-backend → Environment, puis ave-accounts → Environment). Correspondance des noms :

| taksi-backend | ave-accounts | Remarque |
|---|---|---|
| `WHATSAPP_TOKEN` | `ACCOUNTS_WHATSAPP_TOKEN` | même compte Meta |
| `WHATSAPP_PHONE_ID` | `ACCOUNTS_WHATSAPP_PHONE_NUMBER_ID` | même numéro WhatsApp Business |
| `WHATSAPP_OTP_TEMPLATE` (`woyo_otp`) | `ACCOUNTS_WHATSAPP_TEMPLATE` (`ave_otp`) | **nouveau modèle à créer** (voir ci-dessous) |
| `ORANGE_SMS_AUTH_HEADER` | `ACCOUNTS_ORANGE_AUTH_HEADER` | ou `ACCOUNTS_ORANGE_CLIENT_ID` + `_SECRET` |
| `ORANGE_SMS_SENDER` | `ACCOUNTS_ORANGE_SENDER` | défaut `tel:+2240000` |
| `ORANGE_SMS_SENDER_NAME` | `ACCOUNTS_ORANGE_SENDER_NAME` | **laisser vide** : le nom accordé est « WOYO » ; un nom non accordé fait refuser l'envoi |
| `INFOBIP_BASE_URL`, `INFOBIP_API_KEY` | `ACCOUNTS_INFOBIP_BASE_URL`, `ACCOUNTS_INFOBIP_API_KEY` | |
| `INFOBIP_SENDER` | `ACCOUNTS_INFOBIP_SENDER` | défaut `AVE` (à vérifier auprès d'Infobip ; sinon le numéro fourni) |

- **Modèle WhatsApp `ave_otp`** : Business Manager → WhatsApp → Modèles → catégorie **Authentification**, langue **Français**,
  bouton **« Copier le code »** ; attendre l'approbation de Meta. Tant qu'il n'est pas approuvé, WhatsApp refuse (erreur
  132001) et le code part par SMS. ⚠️ Le message part du numéro WhatsApp Business existant, donc sous le nom **WOYO**.
- **Quotas partagés** : la règle d'Orange (3 SMS par jour au même numéro) est comptée séparément par taksi-backend et par
  ce service. Une personne qui utilise WoYo ET AVE le même jour peut donc dépasser la règle côté Orange : Orange refusera
  alors et Infobip prendra le relais. Utiliser le même contrat Orange pour un second service : à confirmer avec Orange Guinée.

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
- Les trois envois reprennent les requêtes de taksi-backend (éprouvées en production chez TAM) et sont testés contre des
  faux ; **depuis ce service, aucun n'a encore été appelé pour de vrai**. Premier essai : sur un numéro de l'équipe, en
  regardant les journaux Render.
- Image Docker non construite ici (pas de Docker sur le poste) : Render la construira au premier déploiement.
- Sauvegarde de la base SQLite : non faite (disque Render seulement). À prévoir avant d'avoir de vrais utilisateurs.
