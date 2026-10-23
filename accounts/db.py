"""Stockage SQLite (suffisant pour démarrer ; PostgreSQL en production à fort trafic). Aucun numéro de téléphone en clair :
uniquement des empreintes HMAC. Les jetons longs ne sont stockés que sous forme de SHA-256."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, sub TEXT UNIQUE,
  phone_hash TEXT UNIQUE, apple_hash TEXT UNIQUE, device_key TEXT UNIQUE,
  created_at INTEGER NOT NULL, apple_refresh TEXT);
CREATE TABLE IF NOT EXISTS refresh_tokens(
  token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS refresh_by_account ON refresh_tokens(account_id);
CREATE TABLE IF NOT EXISTS otp_challenges(
  id TEXT PRIMARY KEY, phone_hash TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS otp_by_phone ON otp_challenges(phone_hash, created_at);
CREATE TABLE IF NOT EXISTS guest_challenges(challenge_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rate_events(key TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS rate_by_key ON rate_events(key, ts);
CREATE TABLE IF NOT EXISTS token_usage(
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, day TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY(account_id, day));
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        with self.connect() as db:
            db.executescript(SCHEMA)
            # Colonnes ajoutées après la création des premières bases : ajoutées sans rien perdre.
            # apple_refresh : révocation Apple (2026-10-23) ; profil (2026-10-23) : nom complet CHIFFRÉ, version des
            # conditions acceptées et dates d'acceptation et de confirmation de l'âge.
            columns = {row["name"] for row in db.execute("PRAGMA table_info(accounts)")}
            for name, kind in (("apple_refresh", "TEXT"), ("full_name", "TEXT"), ("terms_version", "TEXT"),
                               ("terms_accepted_at", "INTEGER"), ("adult_confirmed_at", "INTEGER")):
                if name not in columns:
                    db.execute(f"ALTER TABLE accounts ADD COLUMN {name} {kind}")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise


def now() -> int:
    return int(time.time())
