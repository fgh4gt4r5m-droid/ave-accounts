"""Logique métier : connexion (téléphone+code, Apple, invité), jetons longs, jetons AVE courts, déconnexion, suppression."""
from __future__ import annotations

import base64
import logging
import re
import secrets
import time
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from . import ratelimit
from .config import Settings
from .db import Database, now
from .engine import EngineTokenClient, EngineUnavailable
from .errors import (AccountsError, bad_request, guest_unsupported, invalid_code, invalid_name, invalid_phone, rejected,
                     too_many, unauthorized, unavailable, wrong_code)
from .apple import AppleTokenError
from .otp import OTPDeliveryError, OTPSender
from .security import equal, hmac_hex, new_token, seal, sha256_hex, unseal

log = logging.getLogger("accounts.service")

PHONE_RE = re.compile(r"^\+[1-9][0-9]{7,14}$")
TERMS_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
NAME_MAX = 80
CODE_RE = re.compile(r"^[0-9]{6}$")
CHANNELS = ("sms", "whatsapp")


@dataclass
class Services:
    settings: Settings
    db: Database
    otp: OTPSender
    engine: EngineTokenClient | None
    apple: object | None = None       # AppleVerifier
    attest: object | None = None      # AppAttestVerifier
    apple_tokens: object | None = None  # AppleTokenClient (échange du code, révocation)


class Accounts:
    def __init__(self, s: Services):
        self.s = s
        self.cfg = s.settings

    # ------------------------------------------------------------------ téléphone

    def request_otp(self, phone: str, channel: str, ip: str) -> dict:
        if not isinstance(phone, str) or not PHONE_RE.match(phone):
            raise invalid_phone()
        if channel not in CHANNELS:
            raise invalid_phone()
        phone_hash = hmac_hex(self.cfg.secret, "phone", phone)
        with self.s.db.transaction() as db:
            if (r := ratelimit.hit(db, f"otp:ip:{ip}", self.cfg.ip_otp_per_hour, 3600)) is not None:
                raise too_many(r)
            if (r := ratelimit.hit(db, f"otp:phone:{phone_hash}", self.cfg.phone_otp_per_hour, 3600)) is not None:
                raise too_many(r)
            last = db.execute("SELECT created_at FROM otp_challenges WHERE phone_hash=? ORDER BY created_at DESC LIMIT 1",
                              (phone_hash,)).fetchone()
            if last and now() - last["created_at"] < self.cfg.otp_resend_s:
                raise too_many(self.cfg.otp_resend_s - (now() - last["created_at"]))
            challenge_id = uuid.uuid4().hex
            test_phone = phone in self.cfg.otp_test_phones and self.cfg.otp_test_code is not None
            # Numéro de test (revue Apple, essais) : code fixe connu, aucun message envoyé. Mêmes limites que les autres.
            code = self.cfg.otp_test_code if test_phone else f"{secrets.randbelow(10 ** 6):06d}"
            db.execute("INSERT INTO otp_challenges(id, phone_hash, code_hash, expires_at, created_at) VALUES(?,?,?,?,?)",
                       (challenge_id, phone_hash, hmac_hex(self.cfg.secret, "otp", f"{challenge_id}:{code}"),
                        now() + self.cfg.otp_ttl_s, now()))
        if test_phone:
            return {"challenge_id": challenge_id, "retry_after_s": self.cfg.otp_resend_s}
        try:
            self.s.otp.send(phone, channel, code)
        except OTPDeliveryError:
            with self.s.db.transaction() as db:
                db.execute("DELETE FROM otp_challenges WHERE id=?", (challenge_id,))
            raise unavailable() from None
        return {"challenge_id": challenge_id, "retry_after_s": self.cfg.otp_resend_s}

    def verify_otp(self, challenge_id: str, code: str) -> str:
        if not isinstance(code, str) or not CODE_RE.match(code):
            raise invalid_code()
        failure: AccountsError | None = None
        token: str | None = None
        with self.s.db.transaction() as db:
            row = db.execute("SELECT * FROM otp_challenges WHERE id=?", (challenge_id,)).fetchone()
            # Inconnu, expiré ou déjà utilisé : même réponse qu'un mauvais code (on ne renseigne pas un attaquant).
            if row is None or row["used"] or row["expires_at"] < now():
                failure = wrong_code()
            else:
                # Le compteur d'essais doit être VALIDÉ même quand on refuse : on lève l'erreur APRÈS la transaction
                # (une exception à l'intérieur l'annulerait, et l'attaquant pourrait deviner le code sans limite).
                attempts = row["attempts"] + 1
                db.execute("UPDATE otp_challenges SET attempts=? WHERE id=?", (attempts, challenge_id))
                if attempts > self.cfg.otp_max_attempts:
                    failure = too_many(max(1, row["expires_at"] - now()))
                elif not equal(hmac_hex(self.cfg.secret, "otp", f"{challenge_id}:{code}"), row["code_hash"]):
                    failure = wrong_code()
                else:
                    db.execute("UPDATE otp_challenges SET used=1 WHERE id=?", (challenge_id,))
                    account_id = self._account_for(db, "phone_hash", row["phone_hash"], kind="phone")
                    token = self._issue_refresh(db, account_id, "phone")
        if failure is not None:
            raise failure
        assert token is not None
        return token

    # ------------------------------------------------------------------ Apple

    def sign_in_apple(self, identity_token: str, nonce: str, authorization_code: str | None = None) -> str:
        if self.s.apple is None:
            raise unavailable()
        apple_sub = self.s.apple.verify(identity_token, nonce)
        # Jeton Apple à révoquer plus tard (suppression du compte). Un échec de l'échange ne bloque PAS la connexion :
        # le jeton déjà gardé (connexion précédente) reste valable ; il est journalisé pour être vu.
        apple_refresh = None
        if authorization_code and self.s.apple_tokens is not None:
            try:
                apple_refresh = self.s.apple_tokens.exchange(authorization_code)
            except AppleTokenError as e:
                log.warning("échange du code Apple impossible (%s) : révocation à la suppression non garantie", e)
        with self.s.db.transaction() as db:
            account_id = self._account_for(db, "apple_hash", hmac_hex(self.cfg.secret, "apple", apple_sub), kind="apple")
            if apple_refresh:
                db.execute("UPDATE accounts SET apple_refresh=? WHERE id=?",
                           (seal(self.cfg.secret, "apple-refresh", apple_refresh), account_id))
            return self._issue_refresh(db, account_id, "apple")

    # ------------------------------------------------------------------ invité

    def guest_challenge(self, ip: str) -> str:
        if self.s.attest is None:
            raise guest_unsupported()
        challenge = secrets.token_bytes(32)
        with self.s.db.transaction() as db:
            if (r := ratelimit.hit(db, f"guest:ip:{ip}", self.cfg.ip_guest_per_hour * 3, 3600)) is not None:
                raise too_many(r)
            db.execute("INSERT INTO guest_challenges(challenge_hash, expires_at) VALUES(?,?)",
                       (sha256_hex(challenge), now() + 300))
        return base64.b64encode(challenge).decode()

    def sign_in_guest(self, key_id: str, attestation_b64: str, challenge_b64: str, ip: str) -> str:
        if self.s.attest is None:
            raise guest_unsupported()
        try:
            attestation = base64.b64decode(attestation_b64, validate=True)
            challenge = base64.b64decode(challenge_b64, validate=True)
        except ValueError:
            raise rejected() from None
        with self.s.db.transaction() as db:
            if (r := ratelimit.hit(db, f"guest:signin:{ip}", self.cfg.ip_guest_per_hour, 3600)) is not None:
                raise too_many(r)
            # Défi à usage unique : consommé même si l'attestation échoue (pas de rejeu).
            row = db.execute("SELECT expires_at FROM guest_challenges WHERE challenge_hash=?", (sha256_hex(challenge),)).fetchone()
            db.execute("DELETE FROM guest_challenges WHERE challenge_hash=?", (sha256_hex(challenge),))
            if row is None or row["expires_at"] < now():
                raise rejected()
        self.s.attest.verify(key_id, attestation, challenge)  # lève `rejected`
        with self.s.db.transaction() as db:
            account_id = self._account_for(db, "device_key", hmac_hex(self.cfg.secret, "device", key_id), kind="guest")
            return self._issue_refresh(db, account_id, "guest")

    # ------------------------------------------------------------------ jetons

    def access_token(self, refresh_token: str) -> dict:
        with self.s.db.transaction() as db:
            row = self._refresh_row(db, refresh_token)
            account = db.execute("SELECT id, kind, sub FROM accounts WHERE id=?", (row["account_id"],)).fetchone()
            limit = self.cfg.guest_tokens_per_day if account["kind"] == "guest" else self.cfg.account_tokens_per_day
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            used = db.execute("SELECT count FROM token_usage WHERE account_id=? AND day=?", (account["id"], day)).fetchone()
            if used and used["count"] >= limit:
                tomorrow = (int(time.time()) // 86400 + 1) * 86400
                raise too_many(tomorrow - int(time.time()), code="quota_exceeded")
            sub = account["sub"]  # NULL pour un invité
            account_id = account["id"]
        if self.s.engine is None:
            raise unavailable()
        try:
            token, expires_in = self.s.engine.mint(self.cfg.token_ttl_s, sub=sub, languages=list(self.cfg.token_languages) or None)
        except EngineUnavailable as e:
            raise unavailable(e.retry_after_s) from None
        # Le quota ne se décompte qu'une fois le jeton réellement délivré (une panne du moteur ne le consomme pas).
        with self.s.db.transaction() as db:
            db.execute("INSERT INTO token_usage(account_id, day, count) VALUES(?,?,1) "
                       "ON CONFLICT(account_id, day) DO UPDATE SET count=count+1", (account_id, day))
        return {"token": token, "expires_in": expires_in}

    # ------------------------------------------------------------------ profil

    def profile(self, refresh_token: str) -> dict:
        """Nom complet, conditions acceptées, âge confirmé : relus à la reconnexion (réinstallation, autre iPhone), pour ne
        pas redemander ce qui a déjà été donné."""
        with self.s.db.connect() as db:
            row = self._refresh_row(db, refresh_token)
            account = db.execute("SELECT full_name, terms_version, terms_accepted_at, adult_confirmed_at FROM accounts "
                                 "WHERE id=?", (row["account_id"],)).fetchone()
        return self._profile_body(account)

    def update_profile(self, refresh_token: str, full_name: str | None = None, terms_version: str | None = None,
                       adult_confirmed: bool | None = None) -> dict:
        """Champs absents : inchangés. Le nom est CHIFFRÉ (il faut pouvoir le relire ; jamais journalisé). Accepter des
        conditions note leur version et la date ; l'âge ne se confirme qu'à vrai (on ne « dé-confirme » pas)."""
        updates: dict[str, object] = {}
        if full_name is not None:
            name = " ".join(full_name.split())  # espaces superflus et retours à la ligne retirés
            if not name or len(name) > NAME_MAX or any(unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs") for c in name):
                raise invalid_name()
            updates["full_name"] = seal(self.cfg.secret, "full-name", name)
        if terms_version is not None:
            if not TERMS_VERSION_RE.match(terms_version):
                raise bad_request()
            updates["terms_version"] = terms_version
            updates["terms_accepted_at"] = now()
        if adult_confirmed is not None:
            if adult_confirmed is not True:
                raise bad_request()
            updates["adult_confirmed_at"] = now()
        with self.s.db.transaction() as db:
            row = self._refresh_row(db, refresh_token)
            if updates:
                assignments = ", ".join(f"{column}=?" for column in updates)  # noms de colonnes fixes, jamais reçus
                db.execute(f"UPDATE accounts SET {assignments} WHERE id=?", (*updates.values(), row["account_id"]))
            account = db.execute("SELECT full_name, terms_version, terms_accepted_at, adult_confirmed_at FROM accounts "
                                 "WHERE id=?", (row["account_id"],)).fetchone()
        return self._profile_body(account)

    def _profile_body(self, account) -> dict:
        name = unseal(self.cfg.secret, "full-name", account["full_name"]) if account["full_name"] else None
        return {"full_name": name, "terms_version": account["terms_version"],
                "terms_accepted_at": account["terms_accepted_at"],
                "adult_confirmed": account["adult_confirmed_at"] is not None}

    def sign_out(self, refresh_token: str) -> None:
        with self.s.db.transaction() as db:
            db.execute("DELETE FROM refresh_tokens WHERE token_hash=?", (sha256_hex(refresh_token),))

    def delete_account(self, refresh_token: str) -> None:
        """Efface d'abord côté moteur les données d'apprentissage du sujet (le moteur ne les rattache qu'au `sub`), PUIS le compte.
        Si l'effacement côté moteur échoue, le compte est conservé et l'utilisateur peut réessayer : on ne supprime pas
        l'identité tant que des données liées à son pseudonyme pourraient subsister."""
        with self.s.db.connect() as db:
            row = self._refresh_row(db, refresh_token)
            account = db.execute("SELECT id, sub, kind, apple_refresh FROM accounts WHERE id=?",
                                 (row["account_id"],)).fetchone()
        if account["sub"]:  # les invités n'ont pas de `sub` : rien n'a pu être collecté pour eux
            if self.s.engine is None:
                raise unavailable()
            try:
                self.s.engine.erase_subject_learning(account["sub"])
            except EngineUnavailable as e:
                raise unavailable(e.retry_after_s) from None
        # Sign in with Apple : révoquer le jeton Apple AVANT d'effacer le compte (App Store, règle 5.1.1(v)). En cas d'échec
        # le compte est conservé et l'utilisateur peut réessayer (même logique que l'effacement côté moteur, idempotent).
        if account["apple_refresh"]:
            token = unseal(self.cfg.secret, "apple-refresh", account["apple_refresh"])
            if token is not None:
                if self.s.apple_tokens is None:
                    raise unavailable()
                try:
                    self.s.apple_tokens.revoke(token)
                except AppleTokenError:
                    raise unavailable() from None
            else:
                log.warning("jeton Apple illisible (secret changé ?) : révocation impossible, compte effacé quand même")
        with self.s.db.transaction() as db:
            db.execute("DELETE FROM accounts WHERE id=?", (account["id"],))  # cascade : jetons longs et usage

    # ------------------------------------------------------------------ interne

    def _refresh_row(self, db, refresh_token: str):
        row = db.execute("SELECT * FROM refresh_tokens WHERE token_hash=?", (sha256_hex(refresh_token),)).fetchone()
        if row is None or row["expires_at"] < now():
            raise unauthorized()
        return row

    def _account_for(self, db, column: str, value: str, kind: str) -> str:
        row = db.execute(f"SELECT id FROM accounts WHERE {column}=?", (value,)).fetchone()
        if row:
            return row["id"]
        account_id = uuid.uuid4().hex
        # Pseudonyme transmis au moteur (`sub`) : stable, dérivé de l'identifiant de compte, jamais du numéro de téléphone.
        # Pas de `sub` pour un invité : le consentement d'apprentissage est réservé aux comptes identifiés.
        sub = None if kind == "guest" else hmac_hex(self.cfg.secret, "sub", account_id)[:32]
        db.execute(f"INSERT INTO accounts(id, kind, sub, {column}, created_at) VALUES(?,?,?,?,?)",
                   (account_id, kind, sub, value, now()))
        return account_id

    def _issue_refresh(self, db, account_id: str, kind: str) -> str:
        token = new_token()
        days = self.cfg.guest_refresh_ttl_days if kind == "guest" else self.cfg.refresh_ttl_days
        db.execute("INSERT INTO refresh_tokens(token_hash, account_id, expires_at, created_at) VALUES(?,?,?,?)",
                   (sha256_hex(token), account_id, now() + days * 86400, now()))
        return token
