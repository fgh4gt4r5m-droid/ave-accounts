"""Révocation Sign in with Apple (App Store, règle 5.1.1(v)) : échange du code à la connexion, jeton Apple gardé CHIFFRÉ,
révoqué à la suppression du compte. Aucun appel à Apple : faux client, ou `httpx.MockTransport` pour les requêtes.
Formes d'après la documentation d'Apple (`/auth/token`, `/auth/revoke`) : NON éprouvées contre appleid.apple.com."""
import json
import sqlite3
import urllib.parse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from accounts.apple import APPLE_ISSUER, AppleTokenClient, AppleTokenError, AppleVerifier
from accounts.config import ConfigError, Settings
from accounts.db import Database
from conftest import SECRET, bearer
from test_apple import AUD, Keys, token

EC_KEY = ec.generate_private_key(ec.SECP256R1())
PEM = EC_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()


class FakeAppleTokens:
    def __init__(self):
        self.exchanged: list[str] = []
        self.revoked: list[str] = []
        self.exchange_fail = False
        self.revoke_fail = False

    def exchange(self, code):
        if self.exchange_fail:
            raise AppleTokenError("down")
        self.exchanged.append(code)
        return f"r.apple.{code}"

    def revoke(self, refresh_token):
        if self.revoke_fail:
            raise AppleTokenError("down")
        self.revoked.append(refresh_token)


@pytest.fixture
def apple_env(env):
    fake = FakeAppleTokens()
    return env, fake, env.client(apple=AppleVerifier(AUD, keys=Keys()), apple_tokens=fake)


def sign_in(client, code="code1"):
    body = {"identity_token": token(), "nonce": "n0nce"}
    if code:
        body["authorization_code"] = code
    r = client.post("/auth/apple", json=body)
    assert r.status_code == 200, r.text
    return r.json()["refresh_token"]


def test_code_is_exchanged_and_apple_token_stored_encrypted_then_revoked_on_deletion(apple_env):
    env, fake, client = apple_env
    refresh = sign_in(client)
    assert fake.exchanged == ["code1"]
    dump = "\n".join(sqlite3.connect(env.settings.db_path).iterdump())
    assert "r.apple.code1" not in dump  # jamais en clair
    assert client.delete("/account", headers=bearer(refresh)).status_code == 204
    assert fake.revoked == ["r.apple.code1"]
    assert client.post("/auth/token", headers=bearer(refresh)).status_code == 401


def test_revocation_failure_keeps_the_account_so_the_user_can_retry(apple_env):
    _, fake, client = apple_env
    refresh = sign_in(client)
    fake.revoke_fail = True
    r = client.delete("/account", headers=bearer(refresh))
    assert (r.status_code, r.json()["error"]) == (503, "unavailable")
    assert client.post("/auth/token", headers=bearer(refresh)).status_code == 200  # compte conservé
    fake.revoke_fail = False
    assert client.delete("/account", headers=bearer(refresh)).status_code == 204
    assert fake.revoked == ["r.apple.code1"]


def test_exchange_failure_or_older_app_still_signs_in(apple_env):
    _, fake, client = apple_env
    fake.exchange_fail = True
    refresh = sign_in(client)
    fake.exchange_fail = False
    old_app = sign_in(client, code=None)          # application antérieure : pas de code
    assert fake.exchanged == []
    assert client.delete("/account", headers=bearer(refresh)).status_code == 204
    assert fake.revoked == []                     # rien à révoquer : rien n'a été gardé
    assert client.post("/auth/token", headers=bearer(old_app)).status_code == 401  # même compte Apple, effacé


def test_new_sign_in_replaces_the_stored_apple_token(apple_env):
    _, fake, client = apple_env
    sign_in(client, "code1")
    refresh = sign_in(client, "code2")
    client.delete("/account", headers=bearer(refresh))
    assert fake.revoked == ["r.apple.code2"]


def recorder(responses):
    seen: list[httpx.Request] = []
    queue = list(responses)

    def handler(request):
        seen.append(request)
        status, payload = queue.pop(0)
        return httpx.Response(status, json=payload)

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_client_secret_and_requests_follow_apple_documentation():
    seen, http = recorder([(200, {"refresh_token": "r.1", "access_token": "a"}), (200, {}), (400, {"error": "x"})])
    client = AppleTokenClient("com.tam.ave", "TEAM123456", "KEY1234567", PEM, client=http, clock=lambda: 1_800_000_000)
    assert client.exchange("abc") == "r.1"
    client.revoke("r.1")
    with pytest.raises(AppleTokenError):
        client.revoke("r.1")
    ex, rv = (dict(urllib.parse.parse_qsl(r.content.decode())) for r in seen[:2])
    assert str(seen[0].url) == "https://appleid.apple.com/auth/token"
    assert ex["grant_type"] == "authorization_code" and ex["code"] == "abc" and ex["client_id"] == "com.tam.ave"
    assert str(seen[1].url) == "https://appleid.apple.com/auth/revoke"
    assert rv["token"] == "r.1" and rv["token_type_hint"] == "refresh_token"
    secret = ex["client_secret"]
    assert jwt.get_unverified_header(secret)["kid"] == "KEY1234567"
    claims = jwt.decode(secret, EC_KEY.public_key(), algorithms=["ES256"], audience=APPLE_ISSUER,
                        options={"verify_exp": False, "verify_iat": False})  # horloge du test fixée
    assert claims["iss"] == "TEAM123456" and claims["sub"] == "com.tam.ave"
    assert claims["exp"] - claims["iat"] <= 300


def test_exchange_without_refresh_token_or_unreachable():
    _, http = recorder([(200, {"access_token": "a"})])
    assert AppleTokenClient("c", "t", "k", PEM, client=http).exchange("abc") is None

    def boom(request):
        raise httpx.ConnectError("hors ligne")

    down = AppleTokenClient("c", "t", "k", PEM, client=httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(AppleTokenError):
        down.exchange("abc")


def test_production_refuses_apple_without_revocation_keys():
    base = dict(secret=SECRET, env="production", engine_url="https://engine", engine_key="k", otp_sender="providers",
                infobip_base_url="x.api.infobip.com", infobip_api_key="k")
    Settings(**base).validate()                                     # Apple désactivé : rien à révoquer
    with pytest.raises(ConfigError):
        Settings(apple_audience="com.tam.ave", **base).validate()
    Settings(apple_audience="com.tam.ave", apple_team_id="T", apple_key_id="K", apple_private_key=PEM, **base).validate()


def test_existing_database_gains_the_column(tmp_path):
    path = tmp_path / "ancienne.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE accounts(id TEXT PRIMARY KEY, kind TEXT NOT NULL, sub TEXT UNIQUE, phone_hash TEXT UNIQUE, "
                "apple_hash TEXT UNIQUE, device_key TEXT UNIQUE, created_at INTEGER NOT NULL)")
    old.execute("INSERT INTO accounts VALUES('a', 'phone', 's', 'h', NULL, NULL, 1)")
    old.commit()
    old.close()
    Database(str(path))
    columns = [row[1] for row in sqlite3.connect(path).execute("PRAGMA table_info(accounts)")]
    assert "apple_refresh" in columns
    assert sqlite3.connect(path).execute("SELECT count(*) FROM accounts").fetchone()[0] == 1
    assert json.dumps(columns)  # schéma lisible
