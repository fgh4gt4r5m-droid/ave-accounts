import sqlite3

from conftest import bearer


def test_new_account_has_an_empty_profile(env):
    c = env.client()
    token = env.login(c)
    r = c.get("/account/profile", headers=bearer(token))
    assert r.status_code == 200
    assert r.json() == {"full_name": None, "terms_version": None, "terms_accepted_at": None, "adult_confirmed": False}


def test_name_terms_and_age_are_kept_and_read_back(env):
    c = env.client()
    token = env.login(c)
    r = c.patch("/account/profile", headers=bearer(token),
                json={"full_name": "  Fatou   Camara \n", "terms_version": "2026-10-v1", "adult_confirmed": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["full_name"] == "Fatou Camara"  # espaces superflus retirés
    assert body["terms_version"] == "2026-10-v1" and body["terms_accepted_at"] > 0 and body["adult_confirmed"] is True
    # Nouvelle connexion (réinstallation, autre iPhone) : le profil est retrouvé, rien n'est redemandé.
    again = env.login(c)
    assert c.get("/account/profile", headers=bearer(again)).json() == body


def test_absent_fields_are_unchanged(env):
    c = env.client()
    token = env.login(c)
    c.patch("/account/profile", headers=bearer(token), json={"full_name": "Fatou Camara"})
    r = c.patch("/account/profile", headers=bearer(token), json={"terms_version": "2026-10-v2"})
    assert r.json()["full_name"] == "Fatou Camara" and r.json()["terms_version"] == "2026-10-v2"


def test_name_is_encrypted_at_rest(env):
    c = env.client()
    token = env.login(c)
    c.patch("/account/profile", headers=bearer(token), json={"full_name": "Mariama Diallo"})
    dump = "\n".join(sqlite3.connect(env.settings.db_path).iterdump())
    assert "Mariama" not in dump and "Diallo" not in dump


def test_invalid_values_are_refused(env):
    c = env.client()
    token = env.login(c)
    for name in ["", "   ", "a" * 81, "Fatou\u0000Camara", "Fatou​Camara"]:
        r = c.patch("/account/profile", headers=bearer(token), json={"full_name": name})
        assert (r.status_code, r.json()["error"]) == (400, "invalid_name"), repr(name)
    for version in ["", "v 1", "x" * 33, "../cgu"]:
        r = c.patch("/account/profile", headers=bearer(token), json={"terms_version": version})
        assert (r.status_code, r.json()["error"]) == (400, "bad_request"), version
    # L'âge ne se « dé-confirme » pas.
    r = c.patch("/account/profile", headers=bearer(token), json={"adult_confirmed": False})
    assert (r.status_code, r.json()["error"]) == (400, "bad_request")
    assert c.get("/account/profile", headers=bearer(token)).json()["full_name"] is None


def test_profile_requires_a_valid_long_token(env):
    c = env.client()
    assert c.get("/account/profile").json() == {"error": "unauthorized"}
    assert c.patch("/account/profile", headers=bearer("inconnu"), json={"full_name": "X"}).status_code == 401


def test_deleting_the_account_erases_the_profile(env):
    c = env.client()
    token = env.login(c)
    c.patch("/account/profile", headers=bearer(token), json={"full_name": "Fatou Camara", "adult_confirmed": True})
    assert c.delete("/account", headers=bearer(token)).status_code == 204
    fresh = env.login(c)  # même numéro : un compte NEUF
    assert c.get("/account/profile", headers=bearer(fresh)).json()["full_name"] is None
