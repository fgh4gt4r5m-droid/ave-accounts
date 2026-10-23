"""Vérification du jeton d'identité « Sign in with Apple » : signature RS256 (clés publiques d'Apple), émetteur, audience,
expiration et nonce. Le nonce BRUT vient de l'app ; Apple a reçu son SHA-256 hexadécimal et le recopie dans le jeton."""
from __future__ import annotations

import time
from typing import Protocol

import httpx
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


class AppleTokenError(Exception):
    """Apple injoignable ou refus : la révocation n'a pas pu être faite."""


class AppleTokenClient:
    """Échange du code d'autorisation contre un jeton de rafraîchissement Apple, puis révocation de ce jeton à la
    suppression du compte : exigé par l'App Store pour Sign in with Apple (règle 5.1.1(v)).
    `client_secret` : JWT ES256 signé avec la clé « Sign in with Apple » de l'équipe (fichier .p8), valable 5 minutes."""

    TOKEN_URL = "https://appleid.apple.com/auth/token"
    REVOKE_URL = "https://appleid.apple.com/auth/revoke"

    def __init__(self, client_id: str, team_id: str, key_id: str, private_key_pem: str,
                 client: httpx.Client | None = None, clock=time.time):
        self.client_id, self.team_id, self.key_id = client_id, team_id, key_id
        self.private_key_pem = private_key_pem
        self.client = client or httpx.Client(timeout=10)
        self.clock = clock

    def client_secret(self) -> str:
        now = int(self.clock())
        claims = {"iss": self.team_id, "iat": now, "exp": now + 300, "aud": APPLE_ISSUER, "sub": self.client_id}
        return jwt.encode(claims, self.private_key_pem, algorithm="ES256", headers={"kid": self.key_id})

    def _post(self, url: str, data: dict) -> httpx.Response:
        try:
            return self.client.post(url, data={"client_id": self.client_id, "client_secret": self.client_secret(), **data},
                                    headers={"Accept": "application/json"})
        except httpx.HTTPError as e:
            raise AppleTokenError(type(e).__name__) from e

    def exchange(self, authorization_code: str) -> str | None:
        """Renvoie le jeton de rafraîchissement Apple, ou `None` si Apple n'en donne pas. Le code ne vaut qu'une fois,
        5 minutes."""
        r = self._post(self.TOKEN_URL, {"code": authorization_code, "grant_type": "authorization_code"})
        if r.status_code >= 300:
            raise AppleTokenError(f"HTTP {r.status_code}")
        try:
            token = r.json().get("refresh_token")
        except ValueError as e:
            raise AppleTokenError("réponse illisible") from e
        return token if isinstance(token, str) and token else None

    def revoke(self, refresh_token: str) -> None:
        r = self._post(self.REVOKE_URL, {"token": refresh_token, "token_type_hint": "refresh_token"})
        if r.status_code >= 300:
            raise AppleTokenError(f"HTTP {r.status_code}")
