import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from accounts.apple import APPLE_ISSUER, AppleVerifier
from accounts.security import sha256_hex
from conftest import bearer

AUD = "fr.ave.app"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Keys:
    class _K:
        key = KEY.public_key()

    def get_signing_key_from_jwt(self, token):
        return self._K()


def token(raw_nonce="n0nce", sub="001.apple.sub", aud=AUD, iss=APPLE_ISSUER, exp=None, key=KEY, nonce="auto", alg="RS256"):
    claims = {"iss": iss, "aud": aud, "sub": sub, "exp": exp or int(time.time()) + 600}
    if nonce == "auto":
        claims["nonce"] = sha256_hex(raw_nonce)
    elif nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(claims, key, algorithm=alg)


@pytest.fixture
def client(env):
    return env.client(apple=AppleVerifier(AUD, keys=Keys()))


def test_valid_token_logs_in_and_same_apple_user_is_same_account(env, client):
    r = client.post("/auth/apple", json={"identity_token": token(), "nonce": "n0nce"})
    assert r.status_code == 200
    client.post("/auth/token", headers=bearer(r.json()["refresh_token"]))
    r2 = client.post("/auth/apple", json={"identity_token": token(), "nonce": "n0nce"})
    client.post("/auth/token", headers=bearer(r2.json()["refresh_token"]))
    assert env.engine.calls[0]["sub"] == env.engine.calls[1]["sub"] and env.engine.calls[0]["sub"]
    other = client.post("/auth/apple", json={"identity_token": token(sub="autre"), "nonce": "n0nce"})
    client.post("/auth/token", headers=bearer(other.json()["refresh_token"]))
    assert env.engine.calls[2]["sub"] != env.engine.calls[0]["sub"]


@pytest.mark.parametrize("bad", [
    dict(aud="autre.app"), dict(iss="https://evil.example"), dict(exp=int(time.time()) - 10),
    dict(key=OTHER), dict(nonce="mauvais"), dict(nonce=None), dict(sub=""),
], ids=["audience", "emetteur", "expire", "signature", "nonce-faux", "nonce-absent", "sub-vide"])
def test_invalid_tokens_are_rejected(client, bad):
    r = client.post("/auth/apple", json={"identity_token": token(**bad), "nonce": "n0nce"})
    assert (r.status_code, r.json()["error"]) == (401, "rejected")


def test_wrong_raw_nonce_is_rejected(client):
    assert client.post("/auth/apple", json={"identity_token": token(), "nonce": "autre"}).status_code == 401


def test_algorithm_confusion_is_rejected(client):
    forged = jwt.encode({"iss": APPLE_ISSUER, "aud": AUD, "sub": "x", "exp": int(time.time()) + 60,
                         "nonce": sha256_hex("n0nce")}, "secret-hs256-assez-long-pour-pyjwt-32o", algorithm="HS256")
    assert client.post("/auth/apple", json={"identity_token": forged, "nonce": "n0nce"}).status_code == 401


def test_garbage_token_and_unconfigured_apple(env, client):
    assert client.post("/auth/apple", json={"identity_token": "pas.un.jwt", "nonce": "n"}).status_code == 401
    bare = env.client(apple=None)
    assert bare.post("/auth/apple", json={"identity_token": token(), "nonce": "n0nce"}).status_code == 503
