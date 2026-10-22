"""Envoi des codes à usage unique. Port + deux adaptateurs : `console` (développement SEULEMENT, refusé en production)
et `webhook` (vers VOTRE passerelle SMS/WhatsApp : Twilio, Meta Cloud API, opérateur local… non intégrés ici)."""
from __future__ import annotations

import logging
from typing import Protocol

import httpx

log = logging.getLogger("accounts.otp")


class OTPSender(Protocol):
    def send(self, phone: str, channel: str, code: str) -> None: ...


class OTPDeliveryError(Exception):
    pass


def message(code: str, ttl_s: int) -> str:
    return f"Votre code AVE : {code}. Il expire dans {ttl_s // 60} minutes. Ne le communiquez à personne."


class ConsoleOTPSender:
    """DÉVELOPPEMENT : écrit le code dans le journal. Interdit en production (voir Settings.validate)."""

    def __init__(self, ttl_s: int = 300):
        self.ttl_s = ttl_s

    def send(self, phone: str, channel: str, code: str) -> None:
        log.warning("[DEV] code pour %s•••%s via %s : %s", phone[:4], phone[-2:], channel, code)


class WebhookOTPSender:
    """POST JSON `{to, channel, message}` avec `Authorization: Bearer <clé>` vers votre passerelle. Ne journalise jamais le code."""

    def __init__(self, url: str, key: str | None, ttl_s: int = 300, client: httpx.Client | None = None):
        self.url, self.key, self.ttl_s = url, key, ttl_s
        self.client = client or httpx.Client(timeout=10)

    def send(self, phone: str, channel: str, code: str) -> None:
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        try:
            r = self.client.post(self.url, json={"to": phone, "channel": channel, "message": message(code, self.ttl_s)},
                                 headers=headers)
        except httpx.HTTPError as e:
            raise OTPDeliveryError(type(e).__name__) from e
        if r.status_code >= 300:
            raise OTPDeliveryError(f"HTTP {r.status_code}")
