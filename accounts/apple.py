"""Vérification du jeton d'identité « Sign in with Apple » : signature RS256 (clés publiques d'Apple), émetteur, audience,
expiration et nonce. Le nonce BRUT vient de l'app ; Apple a reçu son SHA-256 hexadécimal et le recopie dans le jeton."""
from __future__ import annotations

from typing import Protocol

import jwt

from .errors import AccountsError, rejected, unavailable
from .security import equal, sha256_hex

APPLE_ISSUER = "https://appleid.apple.com"
APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys"


class SigningKeyProvider(Protocol):
    def get_signing_key_from_jwt(self, token: str): ...


class AppleVerifier:
    def __init__(self, audience: str, keys: SigningKeyProvider | None = None):
        self.audience = audience
        # PyJWKClient met les clés en cache ; injectable pour les tests (aucun appel réseau).
        self.keys = keys or jwt.PyJWKClient(APPLE_JWKS_URL, cache_keys=True, lifespan=3600)

    def verify(self, identity_token: str, raw_nonce: str) -> str:
        """Renvoie l'identifiant Apple stable de l'utilisateur (`sub`) ou lève `rejected`."""
        try:
            key = self.keys.get_signing_key_from_jwt(identity_token)
        except jwt.PyJWKClientConnectionError as e:
            raise unavailable() from e
        except jwt.PyJWTError as e:
            raise rejected() from e
        try:
            claims = jwt.decode(identity_token, key.key, algorithms=["RS256"], audience=self.audience, issuer=APPLE_ISSUER,
                                options={"require": ["exp", "iss", "aud", "sub"]})
        except jwt.PyJWTError as e:
            raise rejected() from e
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not equal(nonce, sha256_hex(raw_nonce)):
            raise rejected()
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise rejected()
        return sub
