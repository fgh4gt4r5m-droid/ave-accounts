# AVE accounts : service de comptes de l'app grand public

> Dépôt PRIVÉ : code de sécurité (connexion, jetons). Ne jamais y committer de clé, de secret ni de certificat privé.

Service **séparé du moteur AVE** (et de WoYo/TaGa) : il authentifie l'utilisateur de l'app AVE et lui remet des **jetons AVE courts**.
Il détient la clé B2B du tenant « AVE grand public » et appelle `POST /v1/token` du moteur ; **l'app ne voit jamais cette clé**.
Spécification : `contrat/CONTRAT.md` §6 du dépôt `african-voice-engine` (contrat partagé app iOS ↔ moteur ↔ ce service). Les apps hôtes (WoYo, TaGa) n'utilisent pas ce service : leur backend appelle `/v1/token` lui-même.

```bash
pip install -e '.[dev]' && python3 -m pytest      # 98 tests, < 5 s
ACCOUNTS_ENV=dev ACCOUNTS_ENGINE_URL=http://127.0.0.1:8787 ACCOUNTS_ENGINE_KEY=<clé du tenant> python3 -m accounts   # :8790
```
En dev, les codes sont écrits dans le journal (`console`) et le secret est éphémère. **En production** le service refuse de démarrer sans secret
(≥ 32 caractères), sans moteur en `https://`, sans clé, ou avec l'envoi par console.

## Routes
`POST /auth/otp/request` · `/auth/otp/verify` · `/auth/apple` · `/auth/guest/challenge` · `/auth/guest` · `/auth/token` (Bearer) · `/auth/signout` (Bearer, 204) ·
`DELETE /account` (Bearer, 204) · `GET /account/profile` et `PATCH /account/profile` (Bearer) · `GET /healthz`. Erreurs : `{error, retry_after_s?}` ; 400 `invalid_phone|invalid_code|wrong_code|bad_request`, 401 `unauthorized` (jeton long) ou
`rejected` (identifiants refusés), 403 `guest_unsupported`, 429 `too_many_attempts|quota_exceeded` (+ `Retry-After`), 503 `unavailable`.

## Configuration (variables d'environnement)
| Variable | Rôle |
|---|---|
| `ACCOUNTS_ENV` | `dev` (défaut) ou `production` |
| `ACCOUNTS_SECRET` | secret HMAC (empreintes, pseudonymes, codes) ≥ 32 caractères ; perdre ou changer ce secret rompt les comptes existants |
| `ACCOUNTS_DB` | fichier SQLite (défaut `accounts.db`) |
| `ACCOUNTS_ENGINE_URL`, `ACCOUNTS_ENGINE_KEY` | moteur AVE et clé B2B du tenant « AVE grand public » (jamais dans le dépôt) |
| `ACCOUNTS_TOKEN_TTL_S`, `ACCOUNTS_TOKEN_LANGUAGES` | durée (600) et langues du jeton court (restriction seulement) |
| `ACCOUNTS_OTP_SENDER` = `console`\|`webhook`, `ACCOUNTS_OTP_WEBHOOK_URL`, `_KEY` | envoi des codes ; `webhook` = POST `{to, channel, message}` vers VOTRE passerelle SMS/WhatsApp |
| `ACCOUNTS_OTP_SENDER=providers` + `ACCOUNTS_WHATSAPP_*`, `ACCOUNTS_ORANGE_*`, `ACCOUNTS_INFOBIP_*`, `ACCOUNTS_SMS_PROVIDERS` | envoi direct, même logique que taksi-backend : WhatsApp Cloud API (modèle d'authentification `ave_otp`), puis SMS Orange Guinée (numéros +224, 3 par jour), puis SMS Infobip (`/sms/2/text/advanced`) ; détail et correspondance des variables dans `DEPLOIEMENT.md` |
| `ACCOUNTS_OTP_TEST_PHONES`, `ACCOUNTS_OTP_TEST_CODE` | numéros de test à code fixe (revue Apple) : aucun message envoyé ; code de 6 chiffres non évident obligatoire |
| `ACCOUNTS_APPLE_AUDIENCE` | identifiant (bundle id) de l'app attendu dans le jeton Apple ; absent ⇒ Apple désactivé (503) |
| `ACCOUNTS_APPLE_TEAM_ID`, `ACCOUNTS_APPLE_KEY_ID`, `ACCOUNTS_APPLE_PRIVATE_KEY_FILE` (ou `_PRIVATE_KEY`) | révocation Sign in with Apple à la suppression du compte (App Store, règle 5.1.1(v)) : clé « Sign in with Apple » (.p8) de l'équipe ; **obligatoire en production si Apple est activé** |
| `ACCOUNTS_APPATTEST_APP_ID`, `ACCOUNTS_APPATTEST_ROOT_PEM`, `ACCOUNTS_APPATTEST_DEVELOPMENT=1` | invité : `<TEAM_ID>.<BUNDLE_ID>`, fichier PEM de la racine « Apple App Attestation Root CA » (à télécharger chez Apple), AAGUID de développement ; absents ⇒ invité désactivé (403) |
| `ACCOUNTS_TRUST_PROXY=1` | lire l'IP dans `X-Forwarded-For` (derrière un reverse proxy de confiance uniquement) |

## Sécurité : ce qui est fait
- Aucun numéro de téléphone en clair : empreintes HMAC ; le numéro n'est transmis qu'à la passerelle d'envoi, au moment de l'envoi. Les jetons longs ne sont stockés que sous forme de SHA-256.
- Code à 6 chiffres, usage unique, 5 minutes, **5 essais** (compteur validé même en cas de refus : test de non-régression), comparaison à temps constant, réponse identique pour code inconnu/expiré/faux.
- Limitation de débit (fenêtre glissante en base) par IP et par numéro, délai de renvoi, plafond de jetons par jour et par compte.
- `sub` transmis au moteur : pseudonyme dérivé de l'identifiant de compte (jamais du numéro). **Pas de `sub` pour un invité** (décision produit : apprentissage réservé aux comptes identifiés).
- Apple : signature RS256 (clés publiques d'Apple, en cache), émetteur, audience, expiration, nonce ; `HS256` refusé.
- Déconnexion et suppression de compte (cascade : jetons, usage). Sign in with Apple : le code d'autorisation est échangé à la connexion, le jeton Apple gardé **chiffré** (AES-256-GCM, clé dérivée du secret) et **révoqué** avant la suppression ; échec de la révocation = compte conservé (503), l'utilisateur réessaie. Pas de documentation d'API exposée.

## Limites honnêtes (à lire avant toute mise en ligne)
- **Envoi des codes** : WhatsApp (Meta), Orange et Infobip sont intégrés (2026-10-23) mais testés seulement contre des faux, d'après leur documentation publique ; **aucun envoi réel** n'a encore été fait. Coût et fiabilité à mesurer sur le terrain.
- **Apple** : la vérification est testée avec des clés locales ; **jamais appelée contre `appleid.apple.com`** depuis l'environnement de développement.
- **App Attest** : testé avec une chaîne de certificats **synthétique**, pas avec une vraie attestation Apple. À valider sur un appareil réel avec la vraie racine avant d'activer le mode invité. Une clé ne s'atteste qu'une fois et l'app en crée une neuve à chaque essai : la protection contre les invités fabriqués en masse repose sur la limitation par IP et les quotas.
- **Profil (2026-10-23, entrée validée par le propriétaire)** : `PATCH /account/profile {full_name?, terms_version?, adult_confirmed?}` → `{full_name, terms_version, terms_accepted_at, adult_confirmed}` ; `GET` relit le même corps. Le nom complet (1 à 80 caractères, espaces superflus retirés, sans caractère invisible : sinon 400 `invalid_name`) est **chiffré** comme le jeton Apple et jamais journalisé ; accepter des conditions note leur version (`[A-Za-z0-9._-]{1,32}`) et la date ; l'âge (18 ans ou plus) ne se confirme qu'à `true`. Champ absent : inchangé. Relu à chaque connexion : une réinstallation ne redemande rien. Effacé avec le compte.
- **Effacement des données d'apprentissage** : `DELETE /account` appelle d'abord `DELETE /v1/subjects/{sub}/learning` du moteur (clé B2B), puis supprime le compte. Si le moteur échoue ou est injoignable, **le compte est conservé** (503) et l'utilisateur peut réessayer. Cela ne retire pas son apport d'un modèle DÉJÀ entraîné (à dire à l'utilisateur). Nécessite un moteur qui expose cette route (branche `endpoints-sujets` du dépôt du moteur) ; sans elle, la suppression de compte échoue.
- **Moteur limité** : `/v1/token` et `/v1/subjects` répondent 429 + `Retry-After` (30 d'avance puis 1/s). Le service réessaie au plus 2 fois, seulement pour une attente ≤ 3 s, sinon renvoie 503 avec `retry_after_s` ; il ne boucle jamais.
- SQLite et un seul processus conviennent pour démarrer ; PostgreSQL au-delà. Sauvegardes, rotation du secret, observabilité : non faites.
- Les réponses 429 `quota_exceeded` sont affichées par l'app comme « trop d'essais » (pas de message dédié côté app).
- Vérifié de bout en bout (2026-10-22) contre le moteur : code → jeton long → jeton court → `ready` accepté ; jeton inventé → `unauthorized` ; avec `endpoints-sujets` et un tenant `learning:"opt_in"` : consentement conservé d'une session à l'autre pour le même compte, puis `DELETE /account` efface les données collectées côté moteur et le jeton long devient invalide.
- Tenant : `python3 tools/make_key.py ave-grand-public customer_service --langs fra --learning opt_in` (outil du moteur).
