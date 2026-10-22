import base64

from conftest import FakeAttest, bearer


def guest_login(c, key_id="key-1"):
    ch = c.post("/auth/guest/challenge").json()["challenge"]
    att = base64.b64encode(b"x").decode()
    return c.post("/auth/guest", json={"key_id": key_id, "attestation": att, "challenge": ch}), ch, att


def test_guest_unsupported_without_attestation_config(env):
    c = env.client()
    assert c.post("/auth/guest/challenge").status_code == 403
    r = c.post("/auth/guest", json={"key_id": "k", "attestation": "eA==", "challenge": "eA=="})
    assert (r.status_code, r.json()["error"]) == (403, "guest_unsupported")


def test_guest_flow_gets_a_token_WITHOUT_sub(env):
    """Décision produit : pas d'apprentissage pour les invités → pas de `sub` (pas d'identifiant stable côté moteur)."""
    c = env.client(attest=FakeAttest())
    r, _, _ = guest_login(c)
    assert r.status_code == 200
    assert c.post("/auth/token", headers=bearer(r.json()["refresh_token"])).status_code == 200
    assert env.engine.calls[0]["sub"] is None


def test_challenge_is_single_use_and_unknown_challenge_is_rejected(env):
    c = env.client(attest=FakeAttest())
    r, ch, att = guest_login(c)
    assert r.status_code == 200
    again = c.post("/auth/guest", json={"key_id": "key-1", "attestation": att, "challenge": ch})
    assert (again.status_code, again.json()["error"]) == (401, "rejected")  # rejeu refusé
    unknown = base64.b64encode(b"n'importe quoi").decode()
    assert c.post("/auth/guest", json={"key_id": "k", "attestation": att, "challenge": unknown}).status_code == 401


def test_failed_attestation_is_rejected_and_burns_the_challenge(env):
    c = env.client(attest=FakeAttest())
    r, ch, att = guest_login(c, key_id="bad")
    assert (r.status_code, r.json()["error"]) == (401, "rejected")
    assert c.post("/auth/guest", json={"key_id": "ok", "attestation": att, "challenge": ch}).status_code == 401


def test_malformed_base64_is_rejected(env):
    c = env.client(attest=FakeAttest())
    ch = c.post("/auth/guest/challenge").json()["challenge"]
    r = c.post("/auth/guest", json={"key_id": "k", "attestation": "!!pas du base64!!", "challenge": ch})
    assert r.status_code == 401


def test_same_device_key_same_guest_account_but_guest_quota_applies(tmp_path):
    from conftest import Env
    e = Env(tmp_path, guest_tokens_per_day=1)
    c = e.client(attest=FakeAttest())
    a = guest_login(c)[0].json()["refresh_token"]
    b = guest_login(c)[0].json()["refresh_token"]
    assert c.post("/auth/token", headers=bearer(a)).status_code == 200
    assert c.post("/auth/token", headers=bearer(b)).status_code == 429  # même compte invité : quota partagé


def test_guest_signin_is_rate_limited_per_ip(tmp_path):
    from conftest import Env
    e = Env(tmp_path, ip_guest_per_hour=2)
    c = e.client(attest=FakeAttest())
    codes = [guest_login(c, key_id=f"k{i}")[0].status_code for i in range(3)]
    assert codes[:2] == [200, 200] and codes[2] == 429
