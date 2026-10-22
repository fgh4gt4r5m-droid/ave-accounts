import sqlite3

from accounts.security import hmac_hex
from conftest import PHONE, SECRET, Env, bearer


def test_invalid_phone_and_channel(env):
    c = env.client()
    for phone in ["abc", "0621234567", "+22", "+0224621234567", "+" + "1" * 16, ""]:
        r = c.post("/auth/otp/request", json={"phone": phone, "channel": "sms"})
        assert (r.status_code, r.json()["error"]) == (400, "invalid_phone"), phone
    assert c.post("/auth/otp/request", json={"phone": PHONE, "channel": "pigeon"}).json()["error"] == "invalid_phone"
    assert c.post("/auth/otp/request", json={"channel": "sms"}).json() == {"error": "bad_request"}


def test_request_then_verify_issues_refresh_token(env):
    c = env.client()
    r = c.post("/auth/otp/request", json={"phone": PHONE, "channel": "whatsapp"})
    assert r.status_code == 200 and r.json()["retry_after_s"] == env.settings.otp_resend_s
    phone, channel, code = env.otp.sent[0]
    assert (phone, channel) == (PHONE, "whatsapp") and len(code) == 6 and code.isdigit()
    v = c.post("/auth/otp/verify", json={"challenge_id": r.json()["challenge_id"], "code": code})
    assert v.status_code == 200 and len(v.json()["refresh_token"]) >= 40


def test_no_phone_number_or_code_or_token_stored_in_clear(env):
    c = env.client()
    refresh = env.login(c)
    dump = "\n".join(sqlite3.connect(env.settings.db_path).iterdump())
    assert PHONE not in dump and PHONE[1:] not in dump
    assert env.otp.last_code not in dump.replace("0" * 6, "")  # le code n'est stocké que sous forme d'empreinte
    assert refresh not in dump  # jeton long : seulement son SHA-256


def test_wrong_code_then_correct_code_works_and_is_single_use(env):
    c = env.client()
    cid = c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"}).json()["challenge_id"]
    good = env.otp.last_code
    bad = "000000" if good != "000000" else "111111"
    r = c.post("/auth/otp/verify", json={"challenge_id": cid, "code": bad})
    assert (r.status_code, r.json()["error"]) == (400, "wrong_code")
    assert c.post("/auth/otp/verify", json={"challenge_id": cid, "code": good}).status_code == 200
    again = c.post("/auth/otp/verify", json={"challenge_id": cid, "code": good})
    assert (again.status_code, again.json()["error"]) == (400, "wrong_code")  # code à usage unique


def test_guessing_is_capped_even_if_the_right_code_comes_later(env):
    """Régression : le compteur d'essais doit survivre au refus (sinon le code se devine sans limite)."""
    c = env.client()
    cid = c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"}).json()["challenge_id"]
    good = env.otp.last_code
    bad = "000000" if good != "000000" else "111111"
    for _ in range(env.settings.otp_max_attempts):
        assert c.post("/auth/otp/verify", json={"challenge_id": cid, "code": bad}).status_code == 400
    r = c.post("/auth/otp/verify", json={"challenge_id": cid, "code": good})  # même le BON code est refusé après la limite
    assert r.status_code == 429 and r.json()["retry_after_s"] >= 1 and "Retry-After" in r.headers


def test_code_format_unknown_and_expired_challenges(env):
    c = env.client()
    cid = c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"}).json()["challenge_id"]
    assert c.post("/auth/otp/verify", json={"challenge_id": cid, "code": "12a456"}).json()["error"] == "invalid_code"
    assert c.post("/auth/otp/verify", json={"challenge_id": cid, "code": "12345"}).json()["error"] == "invalid_code"
    assert c.post("/auth/otp/verify", json={"challenge_id": "inconnu", "code": "123456"}).json()["error"] == "wrong_code"
    sqlite3.connect(env.settings.db_path).execute("UPDATE otp_challenges SET expires_at=1").connection.commit()
    assert c.post("/auth/otp/verify", json={"challenge_id": cid, "code": env.otp.last_code}).json()["error"] == "wrong_code"


def test_resend_cooldown(tmp_path):
    e = Env(tmp_path, otp_resend_s=30)
    c = e.client()
    assert c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"}).status_code == 200
    r = c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"})
    assert r.status_code == 429 and 1 <= r.json()["retry_after_s"] <= 30 and r.headers["Retry-After"]
    assert len(e.otp.sent) == 1  # le second code n'est jamais parti


def test_rate_limits_per_phone_and_per_ip(tmp_path):
    e = Env(tmp_path, phone_otp_per_hour=2)
    c = e.client()
    codes = [c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert c.post("/auth/otp/request", json={"phone": "+224622222222", "channel": "sms"}).status_code == 200  # autre numéro


def test_ip_rate_limit(tmp_path):
    (tmp_path / "b").mkdir()
    e = Env(tmp_path / "b", ip_otp_per_hour=2)
    c = e.client()
    statuses = [c.post("/auth/otp/request", json={"phone": f"+22462123456{i}", "channel": "sms"}).status_code for i in range(3)]
    assert statuses == [200, 200, 429]


def test_sender_failure_is_a_503_and_leaves_no_challenge(env):
    env.otp.fail = True
    c = env.client()
    r = c.post("/auth/otp/request", json={"phone": PHONE, "channel": "sms"})
    assert (r.status_code, r.json()["error"]) == (503, "unavailable")
    assert sqlite3.connect(env.settings.db_path).execute("SELECT COUNT(*) FROM otp_challenges").fetchone()[0] == 0


def test_same_phone_same_account_and_sub_is_not_derived_from_the_phone(env):
    c = env.client()
    r1 = env.login(c)
    r2 = env.login(c)
    assert r1 != r2  # un jeton long par connexion
    c.post("/auth/token", headers=bearer(r1))
    c.post("/auth/token", headers=bearer(r2))
    sub1, sub2 = (call["sub"] for call in env.engine.calls)
    assert sub1 == sub2 and len(sub1) == 32
    assert sub1 != hmac_hex(SECRET, "phone", PHONE)[:32] and PHONE not in sub1
    other = env.login(c, "+224622222222")
    c.post("/auth/token", headers=bearer(other))
    assert env.engine.calls[-1]["sub"] != sub1
