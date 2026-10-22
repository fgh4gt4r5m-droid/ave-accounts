"""Primitives : empreintes HMAC à séparation de domaines, jetons aléatoires, comparaison à temps constant."""
from __future__ import annotations

import hashlib
import hmac
import secrets


def hmac_hex(secret: bytes, purpose: str, data: str) -> str:
    """HMAC-SHA256 avec séparation de domaines : une empreinte de numéro n'est jamais un pseudonyme ni un code."""
    key = hashlib.sha256(secret + b"|" + purpose.encode()).digest()
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(data: str | bytes) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def equal(a: str | bytes, b: str | bytes) -> bool:
    a = a.encode() if isinstance(a, str) else a
    b = b.encode() if isinstance(b, str) else b
    return hmac.compare_digest(a, b)
