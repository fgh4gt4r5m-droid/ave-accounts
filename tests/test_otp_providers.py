"""Envoi des codes par WhatsApp (Meta), Orange et Infobip : formes des requêtes, repli, jeton Orange, numéros de test.
Aucun réseau : `httpx.MockTransport` joue les fournisseurs. Les formes suivent leur documentation publique ; elles n'ont
PAS été éprouvées contre les vrais services (à faire avec de vrais comptes, sur un numéro de test)."""
import base64
import json
import logging

import httpx
import pytest

from accounts.api import build_otp_sender
from accounts.config import ConfigError, Settings
from accounts.otp import (FallbackOTPSender, InfobipSMSSender, OrangeSMSSender, OTPDeliveryError, WhatsAppCloudSender)
from conftest import PHONE, SECRET, Env

CODE = "482913"


def recorder(responses):
    """Transport qui enregistre les requêtes et répond dans l'ordre (status, json)."""
    seen: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        status, payload = queue.pop(0) if queue else (200, {})
        return httpx.Response(status, json=payload)

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_whatsapp_authentication_template_carries_the_code_in_body_and_button():
    seen, client = recorder([(200, {"messages": [{"id": "wamid.1"}]})])
    WhatsAppCloudSender("jeton-meta", "1234567890", "ave_otp", "fr", "v21.0", client=client).send(PHONE, "whatsapp", CODE)
    req = seen[0]
    assert str(req.url) == "https://graph.facebook.com/v21.0/1234567890/messages"
    assert req.headers["Authorization"] == "Bearer jeton-meta"
    body = json.loads(req.content)
    assert body["to"] == PHONE[1:] and body["type"] == "template" and body["messaging_product"] == "whatsapp"
    assert body["template"]["name"] == "ave_otp" and body["template"]["language"] == {"code": "fr"}
    comps = body["template"]["components"]
    assert comps[0] == {"type": "body", "parameters": [{"type": "text", "text": CODE}]}
    assert comps[1] == {"type": "button", "sub_type": "url", "index": "0", "parameters": [{"type": "text", "text": CODE}]}


def test_whatsapp_error_is_a_delivery_error():
    _, client = recorder([(400, {"error": {"message": "template not approved"}})])
    with pytest.raises(OTPDeliveryError):
        WhatsAppCloudSender("t", "1", "ave_otp", client=client).send(PHONE, "whatsapp", CODE)


def test_infobip_sms_v2_request_like_taksi_backend():
    seen, client = recorder([(200, {"messages": [{"messageId": "m1", "status": {"groupName": "PENDING"}}]})])
    InfobipSMSSender("abc123.api.infobip.com", " cle-infobip ", "AVE", ttl_s=300, client=client).send(PHONE, "sms", CODE)
    req = seen[0]
    assert str(req.url) == "https://abc123.api.infobip.com/sms/2/text/advanced"
    assert req.headers["Authorization"] == "App cle-infobip"
    msg = json.loads(req.content)["messages"][0]
    assert msg["from"] == "AVE" and msg["destinations"] == [{"to": PHONE[1:]}]
    assert CODE in msg["text"] and "5 minutes" in msg["text"]


def test_infobip_rejection_inside_a_2xx_is_a_failure():
    _, client = recorder([(200, {"messages": [{"status": {"groupName": "REJECTED"}}]})])
    with pytest.raises(OTPDeliveryError):
        InfobipSMSSender("https://x.api.infobip.com/", "k", "AVE", client=client).send(PHONE, "sms", CODE)


def test_orange_token_then_sms_with_encoded_sender_and_token_reuse():
    seen, client = recorder([(200, {"access_token": "tok1", "expires_in": "3600"}), (201, {}), (201, {})])
    now = [1000.0]
    sender = OrangeSMSSender(" id ", "sec ret", "tel:+2240000", "AVE", client=client, clock=lambda: now[0])
    sender.send(PHONE, "sms", CODE)
    sender.send(PHONE, "sms", CODE)
    token_req, sms_req, sms_req2 = seen  # un seul jeton pour deux envois
    assert str(token_req.url) == "https://api.orange.com/oauth/v3/token"
    # Espaces retirés partout (le secret copié depuis la page d'Orange en contenait, constaté chez TAM).
    assert token_req.headers["Authorization"] == "Basic " + base64.b64encode(b"id:secret").decode()
    assert token_req.content == b"grant_type=client_credentials"
    assert str(sms_req.url) == "https://api.orange.com/smsmessaging/v1/outbound/tel%3A%2B2240000/requests"
    assert sms_req.headers["Authorization"] == "Bearer tok1"
    body = json.loads(sms_req.content)["outboundSMSMessageRequest"]
    assert body["address"] == f"tel:{PHONE}" and body["senderAddress"] == "tel:+2240000" and body["senderName"] == "AVE"
    assert CODE in body["outboundSMSTextMessage"]["message"]


def test_orange_token_renewed_when_expired_and_after_a_401_but_never_loops():
    seen, client = recorder([(200, {"access_token": "a", "expires_in": 3600}), (201, {}),
                             (200, {"access_token": "b", "expires_in": 3600}), (401, {}),
                             (200, {"access_token": "c", "expires_in": 3600}), (201, {}),
                             (401, {}), (200, {"access_token": "d", "expires_in": 3600}), (401, {})])
    now = [0.0]
    sender = OrangeSMSSender("id", "secret", "2240000", client=client, clock=lambda: now[0])
    sender.send(PHONE, "sms", CODE)                 # jeton a
    now[0] = 4000                                   # a expiré (marge d'une minute) : jeton b, refusé (401) → jeton c
    sender.send(PHONE, "sms", CODE)
    assert [r.headers["Authorization"] for r in seen if "smsmessaging" in str(r.url)] == [
        "Bearer a", "Bearer b", "Bearer c"]
    with pytest.raises(OTPDeliveryError):           # 401, nouveau jeton d, encore 401 : on abandonne
        sender.send(PHONE, "sms", CODE)
    assert "senderName" not in json.loads(seen[1].content)["outboundSMSMessageRequest"]


def test_orange_ready_made_header_guinea_only_and_three_per_day():
    seen, client = recorder([(200, {"access_token": "t", "expires_in": 3600})] + [(201, {})] * 3)
    sender = OrangeSMSSender(None, None, "2240000", client=client, auth_header="Basic  QUJD REVG ")
    assert seen == [] and not sender.supports("+33612345678") and sender.supports(PHONE)
    with pytest.raises(OTPDeliveryError):
        sender.send("+33612345678", "sms", CODE)      # étranger : jamais envoyé par Orange
    assert seen == []
    for _ in range(3):
        sender.send(PHONE, "sms", CODE)
    assert seen[0].headers["Authorization"] == "Basic QUJDREVG"
    with pytest.raises(OTPDeliveryError):
        sender.send(PHONE, "sms", CODE)               # 4e SMS du jour au même numéro : refusé avant tout appel
    assert len(seen) == 4


def test_fallback_skips_orange_for_a_foreign_number():
    orange, infobip = OrangeSMSSender(None, None, "2240000", auth_header="Basic x"), Stub("infobip")
    FallbackOTPSender(None, [("orange", orange), ("infobip", infobip)]).send("+33612345678", "sms", CODE)
    assert infobip.calls == ["sms"]


class Stub:
    def __init__(self, name, fail=False):
        self.name, self.fail, self.calls = name, fail, []

    def send(self, phone, channel, code):
        self.calls.append(channel)
        if self.fail:
            raise OTPDeliveryError(f"{self.name} en panne")


def test_fallback_whatsapp_then_sms_providers_in_order(caplog):
    wa, orange, infobip = Stub("wa", fail=True), Stub("orange", fail=True), Stub("infobip")
    caplog.set_level(logging.INFO, logger="accounts.otp")
    FallbackOTPSender(wa, [("orange", orange), ("infobip", infobip)]).send(PHONE, "whatsapp", CODE)
    assert (wa.calls, orange.calls, infobip.calls) == (["whatsapp"], ["whatsapp"], ["whatsapp"])
    logs = caplog.text
    assert CODE not in logs and PHONE not in logs  # ni code ni numéro complet dans les journaux


def test_fallback_sms_channel_skips_whatsapp_and_fails_honestly():
    wa, orange = Stub("wa"), Stub("orange", fail=True)
    with pytest.raises(OTPDeliveryError):
        FallbackOTPSender(wa, [("orange", orange)]).send(PHONE, "sms", CODE)
    assert wa.calls == []
    with pytest.raises(OTPDeliveryError):
        FallbackOTPSender(None, []).send(PHONE, "whatsapp", CODE)


def test_config_providers_and_test_phones_are_validated():
    base = dict(secret=SECRET)
    with pytest.raises(ConfigError):
        Settings(otp_sender="providers", **base).validate()            # aucun fournisseur
    with pytest.raises(ConfigError):
        Settings(otp_sender="providers", infobip_base_url="https://x", infobip_api_key="k",
                 sms_providers=("orange", "pigeon"), **base).validate()
    with pytest.raises(ConfigError):
        Settings(otp_test_phones=(PHONE,), **base).validate()          # numéro de test sans code
    with pytest.raises(ConfigError):
        Settings(otp_test_phones=(PHONE,), otp_test_code="123456", **base).validate()  # code devinable
    Settings(otp_test_phones=(PHONE,), otp_test_code="582047", **base).validate()
    prod = Settings(env="production", engine_url="https://engine", engine_key="k", otp_sender="providers",
                    orange_client_id="id", orange_client_secret="s", **base).validate()
    sender = build_otp_sender(prod)
    assert isinstance(sender, FallbackOTPSender) and sender.whatsapp is None
    assert [name for name, _ in sender.sms] == ["orange"]  # Infobip non configuré : absent de la chaîne


def test_from_env_reads_provider_settings():
    s = Settings.from_env({
        "ACCOUNTS_SECRET": "x" * 40, "ACCOUNTS_OTP_SENDER": "providers",
        "ACCOUNTS_WHATSAPP_TOKEN": "t", "ACCOUNTS_WHATSAPP_PHONE_NUMBER_ID": "99",
        "ACCOUNTS_SMS_PROVIDERS": "infobip, orange", "ACCOUNTS_INFOBIP_BASE_URL": "https://b", "ACCOUNTS_INFOBIP_API_KEY": "k",
        "ACCOUNTS_OTP_TEST_PHONES": "+224600000001, +224600000002", "ACCOUNTS_OTP_TEST_CODE": "582047"})
    assert s.whatsapp_ready and s.infobip_ready and not s.orange_ready
    assert s.sms_providers == ("infobip", "orange") and s.whatsapp_template == "ave_otp"
    assert s.otp_test_phones == ("+224600000001", "+224600000002")


def test_test_phone_gets_the_fixed_code_without_any_message(tmp_path):
    env = Env(tmp_path, otp_test_phones=("+224600000001",), otp_test_code="582047")
    c = env.client()
    r = c.post("/auth/otp/request", json={"phone": "+224600000001", "channel": "sms"})
    assert r.status_code == 200 and env.otp.sent == []
    v = c.post("/auth/otp/verify", json={"challenge_id": r.json()["challenge_id"], "code": "582047"})
    assert v.status_code == 200
    # Un numéro ordinaire reçoit toujours un code aléatoire par le fournisseur.
    r2 = c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"})
    assert r2.status_code == 200 and [p for p, _, _ in env.otp.sent] == [PHONE]
