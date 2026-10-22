import sqlite3

from conftest import PHONE, bearer


def test_access_token_goes_through_the_engine_with_a_pseudonym(env):
    c = env.client()
    refresh = env.login(c)
    r = c.post("/auth/token", headers=bearer(refresh))
    assert r.status_code == 200 and r.json() == {"token": "t1.fake1", "expires_in": 600}
    call = env.engine.calls[0]
    assert call["ttl_s"] == 600 and call["sub"] and call["languages"] is None


def test_missing_wrong_and_expired_bearer(env):
    c = env.client()
    refresh = env.login(c)
    for headers in [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}, bearer("inconnu")]:
        r = c.post("/auth/token", headers=headers)
        assert (r.status_code, r.json()["error"]) == (401, "unauthorized"), headers
    sqlite3.connect(env.settings.db_path).execute("UPDATE refresh_tokens SET expires_at=1").connection.commit()
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 401


def test_signout_revokes_the_long_token_and_is_idempotent(env):
    c = env.client()
    refresh = env.login(c)
    assert c.post("/auth/signout", headers=bearer(refresh)).status_code == 204
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 401
    assert c.post("/auth/signout", headers=bearer(refresh)).status_code == 204


def test_delete_account_erases_everything_and_a_new_login_is_a_new_person(env):
    c = env.client()
    refresh = env.login(c)
    c.post("/auth/token", headers=bearer(refresh))
    old_sub = env.engine.calls[0]["sub"]
    assert c.delete("/account", headers=bearer(refresh)).status_code == 204
    db = sqlite3.connect(env.settings.db_path)
    for table in ("accounts", "refresh_tokens", "token_usage"):
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
    assert c.delete("/account", headers=bearer(refresh)).status_code == 401
    new = env.login(c)
    c.post("/auth/token", headers=bearer(new))
    assert env.engine.calls[-1]["sub"] != old_sub  # l'ancien pseudonyme n'est pas réutilisé


def test_quota_per_day_and_engine_failure_does_not_consume_it(tmp_path):
    from conftest import Env
    e = Env(tmp_path, account_tokens_per_day=2)
    c = e.client()
    refresh = e.login(c)
    e.engine.fail = True
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 503
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 503
    e.engine.fail = False
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 200
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 200
    r = c.post("/auth/token", headers=bearer(refresh))
    assert (r.status_code, r.json()["error"]) == (429, "quota_exceeded") and r.json()["retry_after_s"] >= 1


def test_engine_not_configured_is_503(env):
    c = env.client(engine=None)
    refresh = env.login(c)
    assert c.post("/auth/token", headers=bearer(refresh)).json() == {"error": "unavailable"}


def test_languages_restriction_is_forwarded(tmp_path):
    from conftest import Env
    e = Env(tmp_path, token_languages=("fra",))
    c = e.client()
    c.post("/auth/token", headers=bearer(e.login(c)))
    assert e.engine.calls[0]["languages"] == ["fra"]


def test_healthz_and_hidden_docs(env):
    c = env.client()
    assert c.get("/healthz").json() == {"ok": True}
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_deleting_an_account_first_erases_learning_data_for_its_sub(env):
    c = env.client()
    refresh = env.login(c)
    c.post("/auth/token", headers=bearer(refresh))
    sub = env.engine.calls[0]["sub"]
    assert c.delete("/account", headers=bearer(refresh)).status_code == 204
    assert env.engine.erased == [sub]  # le moteur a été prié d'effacer CE pseudonyme


def test_failed_erasure_keeps_the_account_so_the_user_can_retry(env):
    c = env.client()
    refresh = env.login(c)
    env.engine.erase_fail = True
    r = c.delete("/account", headers=bearer(refresh))
    assert (r.status_code, r.json()["error"]) == (503, "unavailable")
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 200  # compte et jeton intacts
    env.engine.erase_fail = False
    assert c.delete("/account", headers=bearer(refresh)).status_code == 204
    assert c.post("/auth/token", headers=bearer(refresh)).status_code == 401


def test_erasure_impossible_without_engine_blocks_deletion_of_identified_accounts(env):
    c = env.client(engine=None)
    refresh = env.login(c)
    assert c.delete("/account", headers=bearer(refresh)).status_code == 503


def test_guest_deletion_needs_no_erasure(env):
    from conftest import FakeAttest
    import base64
    c = env.client(attest=FakeAttest())
    ch = c.post("/auth/guest/challenge").json()["challenge"]
    refresh = c.post("/auth/guest", json={"key_id": "k", "attestation": base64.b64encode(b"x").decode(), "challenge": ch}).json()["refresh_token"]
    assert c.delete("/account", headers=bearer(refresh)).status_code == 204
    assert env.engine.erased == []


def test_engine_rate_limit_is_surfaced_with_a_retry_delay(env):
    c = env.client()
    refresh = env.login(c)
    env.engine.fail = True
    env.engine.retry_after = 7
    r = c.post("/auth/token", headers=bearer(refresh))
    assert (r.status_code, r.json()) == (503, {"error": "unavailable", "retry_after_s": 7}) and r.headers["Retry-After"] == "7"
