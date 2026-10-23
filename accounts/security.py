"""Primitives : empreintes HMAC à séparation de domaines, jetons aléatoires, comparaison à temps constant, chiffrement
des rares données qu'il faut pouvoir relire."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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


def _sealing_key(secret: bytes, purpose: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"ave-accounts|{purpose}".encode()).derive(secret)


def seal(secret: bytes, purpose: str, plaintext: str) -> str:
    """Chiffre (AES-256-GCM, clé dérivée du secret du service) une donnée qu'il FAUT pouvoir relire, comme le jeton Apple
    à révoquer : une empreinte ne suffirait pas. Changer le secret rend ces données illisibles, comme le reste."""
    nonce = os.urandom(12)
    sealed = AESGCM(_sealing_key(secret, purpose)).encrypt(nonce, plaintext.encode(), purpose.encode())
    return base64.urlsafe_b64encode(nonce + sealed).decode()


def unseal(secret: bytes, purpose: str, token: str) -> str | None:
    """Déchiffre ; `None` si la donnée est illisible (secret changé, valeur altérée)."""
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        return AESGCM(_sealing_key(secret, purpose)).decrypt(raw[:12], raw[12:], purpose.encode()).decode()
    except (InvalidTag, ValueError):
        return None
