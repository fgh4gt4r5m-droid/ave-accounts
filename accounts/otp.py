"""Envoi des codes à usage unique. Port + adaptateurs :
- `console` : développement SEULEMENT (refusé en production) ;
- `webhook` : vers une passerelle à vous (POST `{to, channel, message}`) ;
- `providers` : WhatsApp Cloud API (Meta), SMS Orange (API Orange Developer) et SMS Infobip, avec repli de l'un à l'autre.
Aucun adaptateur ne journalise le code ni le numéro complet."""
from __future__ import annotations

import base64
import logging
import threading
import time
from typing import Protocol
from urllib.parse import quote

import httpx

log = logging.getLogger("accounts.otp")


class OTPSender(Protocol):
    def send(self, phone: str, channel: str, code: str) -> None: ...


class OTPDeliveryError(Exception):
    pass


def message(code: str, ttl_s: int) -> str:
    return f"Votre code AVE : {code}. Il expire dans {ttl_s // 60} minutes. Ne le communiquez à personne."


def masked(phone: str) -> str:
    return f"{phone[:4]}•••{phone[-2:]}"


class ConsoleOTPSender:
    """DÉVELOPPEMENT : écrit le code dans le journal. Interdit en production (voir Settings.validate)."""

    def __init__(self, ttl_s: int = 300):
        self.ttl_s = ttl_s

    def send(self, phone: str, channel: str, code: str) -> None:
        log.warning("[DEV] code pour %s via %s : %s", masked(phone), channel, code)


def _post(client: httpx.Client, url: str, **kwargs) -> httpx.Response:
    try:
        return client.post(url, **kwargs)
    except httpx.HTTPError as e:
        raise OTPDeliveryError(type(e).__name__) from e


class WebhookOTPSender:
    """POST JSON `{to, channel, message}` avec `Authorization: Bearer <clé>` vers votre passerelle."""

    def __init__(self, url: str, key: str | None, ttl_s: int = 300, client: httpx.Client | None = None):
        self.url, self.key, self.ttl_s = url, key, ttl_s
        self.client = client or httpx.Client(timeout=10)

    def send(self, phone: str, channel: str, code: str) -> None:
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        r = _post(self.client, self.url, json={"to": phone, "channel": channel, "message": message(code, self.ttl_s)},
                  headers=headers)
        if r.status_code >= 300:
            raise OTPDeliveryError(f"HTTP {r.status_code}")


class WhatsAppCloudSender:
    """Modèle d'AUTHENTIFICATION WhatsApp (Meta Cloud API) avec bouton « copier le code ».
    Le modèle (nom, langue) doit être approuvé par Meta ; son texte est fixé par Meta, d'où un corps sans message libre.
    Le code va dans le corps ET dans le paramètre du bouton (exigence de Meta pour ce type de modèle)."""

    def __init__(self, token: str, phone_number_id: str, template: str, language: str = "fr",
                 api_version: str = "v21.0", client: httpx.Client | None = None):
        self.token, self.phone_number_id = token, phone_number_id
        self.template, self.language, self.api_version = template, language, api_version
        self.client = client or httpx.Client(timeout=10)

    def send(self, phone: str, channel: str, code: str) -> None:
        url = f"https://graph.facebook.com/{self.api_version}/{self.phone_number_id}/messages"
        body = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": phone.lstrip("+"),
            "type": "template",
            "template": {
                "name": self.template,
                "language": {"code": self.language},
                "components": [
                    {"type": "body", "parameters": [{"type": "text", "text": code}]},
                    {"type": "button", "sub_type": "url", "index": "0", "parameters": [{"type": "text", "text": code}]},
                ],
            },
        }
        r = _post(self.client, url, json=body, headers={"Authorization": f"Bearer {self.token}"})
        if r.status_code >= 300:
            raise OTPDeliveryError(f"WhatsApp HTTP {r.status_code}")


class InfobipSMSSender:
    """SMS Infobip (API `/sms/3/messages`, en-tête `Authorization: App <clé>`). `base_url` : l'URL propre au compte
    (ex. `https://xxxxx.api.infobip.com`), visible dans le portail Infobip."""

    def __init__(self, base_url: str, api_key: str, sender: str, ttl_s: int = 300, client: httpx.Client | None = None):
        self.base_url, self.api_key, self.sender, self.ttl_s = base_url.rstrip("/"), api_key, sender, ttl_s
        self.client = client or httpx.Client(timeout=10)

    def send(self, phone: str, channel: str, code: str) -> None:
        body = {"messages": [{"sender": self.sender, "destinations": [{"to": phone.lstrip("+")}],
                              "content": {"text": message(code, self.ttl_s)}}]}
        r = _post(self.client, f"{self.base_url}/sms/3/messages", json=body,
                  headers={"Authorization": f"App {self.api_key}", "Accept": "application/json"})
        if r.status_code >= 300:
            raise OTPDeliveryError(f"Infobip HTTP {r.status_code}")


class OrangeSMSSender:
    """SMS Orange (API « SMS » d'Orange Developer, Afrique et Moyen-Orient). Jeton OAuth2 `client_credentials` valable
    une heure, gardé en mémoire et renouvelé avant expiration (ou après un 401). `sender_number` : numéro d'expéditeur du
    pays sans « + » (Guinée : `2240000`). `sender_name` : nom d'expéditeur validé par Orange (11 caractères max), facultatif."""

    TOKEN_URL = "https://api.orange.com/oauth/v3/token"

    def __init__(self, client_id: str, client_secret: str, sender_number: str, sender_name: str | None = None,
                 ttl_s: int = 300, client: httpx.Client | None = None, clock=time.monotonic):
        self.client_id, self.client_secret = client_id, client_secret
        self.sender_number = sender_number.lstrip("+")
        self.sender_name, self.ttl_s = sender_name, ttl_s
        self.client = client or httpx.Client(timeout=10)
        self.clock = clock
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()  # uvicorn peut servir plusieurs requêtes en parallèle (fils de travail)

    def _access_token(self, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and self.clock() < self._expires_at:
                return self._token
            basic = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
            r = _post(self.client, self.TOKEN_URL, data={"grant_type": "client_credentials"},
                      headers={"Authorization": f"Basic {basic}", "Accept": "application/json"})
            if r.status_code >= 300:
                raise OTPDeliveryError(f"Orange jeton HTTP {r.status_code}")
            try:
                payload = r.json()
                token = payload["access_token"]
            except (ValueError, KeyError, TypeError) as e:
                raise OTPDeliveryError("Orange jeton illisible") from e
            self._token = token
            # Marge d'une minute : un jeton qui expire pendant l'envoi ferait échouer le code.
            self._expires_at = self.clock() + max(int(payload.get("expires_in", 3600)) - 60, 60)
            return self._token

    def send(self, phone: str, channel: str, code: str) -> None:
        url = f"https://api.orange.com/smsmessaging/v1/outbound/{quote('tel:+' + self.sender_number, safe='')}/requests"
        request = {"address": f"tel:+{phone.lstrip('+')}", "senderAddress": f"tel:+{self.sender_number}",
                   "outboundSMSTextMessage": {"message": message(code, self.ttl_s)}}
        if self.sender_name:
            request["senderName"] = self.sender_name
        body = {"outboundSMSMessageRequest": request}
        for attempt in range(2):
            token = self._access_token(force=attempt == 1)
            r = _post(self.client, url, json=body, headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 401 and attempt == 0:
                continue  # jeton expiré côté Orange : un seul renouvellement, jamais de boucle
            if r.status_code >= 300:
                raise OTPDeliveryError(f"Orange HTTP {r.status_code}")
            return


class FallbackOTPSender:
    """Essaie les fournisseurs dans l'ordre. Canal `whatsapp` : WhatsApp puis les SMS ; canal `sms` : les SMS seulement.
    Échec de tous : `OTPDeliveryError` (l'app dit honnêtement qu'aucun code n'a pu partir)."""

    def __init__(self, whatsapp: OTPSender | None, sms: list[tuple[str, OTPSender]]):
        self.whatsapp, self.sms = whatsapp, sms

    def send(self, phone: str, channel: str, code: str) -> None:
        chain: list[tuple[str, OTPSender]] = []
        if channel == "whatsapp" and self.whatsapp is not None:
            chain.append(("whatsapp", self.whatsapp))
        chain.extend(self.sms)
        if not chain:
            raise OTPDeliveryError("aucun fournisseur pour ce canal")
        for name, sender in chain:
            try:
                sender.send(phone, channel, code)
                log.info("code envoyé à %s par %s", masked(phone), name)
                return
            except OTPDeliveryError as e:
                log.warning("envoi du code par %s impossible (%s) : fournisseur suivant", name, e)
        raise OTPDeliveryError("tous les fournisseurs ont échoué")
