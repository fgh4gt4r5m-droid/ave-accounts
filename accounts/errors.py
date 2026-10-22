"""Erreurs du service, traduites en réponses JSON `{error, retry_after_s?}` (contrat §6)."""
from __future__ import annotations


class AccountsError(Exception):
    def __init__(self, status: int, code: str, retry_after_s: int | None = None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.retry_after_s = retry_after_s


def invalid_phone() -> AccountsError: return AccountsError(400, "invalid_phone")
def invalid_code() -> AccountsError: return AccountsError(400, "invalid_code")
def wrong_code() -> AccountsError: return AccountsError(400, "wrong_code")
def rejected() -> AccountsError: return AccountsError(401, "rejected")  # identifiants refusés (Apple, attestation)
def unauthorized() -> AccountsError: return AccountsError(401, "unauthorized")  # jeton long absent, inconnu, expiré, révoqué
def guest_unsupported() -> AccountsError: return AccountsError(403, "guest_unsupported")
def unavailable(retry_after_s: int | None = None) -> AccountsError:
    return AccountsError(503, "unavailable", retry_after_s)
def too_many(retry_after_s: int, code: str = "too_many_attempts") -> AccountsError:
    return AccountsError(429, code, max(1, int(retry_after_s)))
