import pytest

from accounts.config import ConfigError, Settings
from accounts.db import Database
from accounts import ratelimit

OK = dict(ACCOUNTS_ENV="production", ACCOUNTS_SECRET="x" * 40, ACCOUNTS_ENGINE_URL="https://ave.example",
          ACCOUNTS_ENGINE_KEY="cle", ACCOUNTS_OTP_SENDER="webhook", ACCOUNTS_OTP_WEBHOOK_URL="https://sms.example/send")


def test_production_config_ok():
    s = Settings.from_env(dict(OK))
    assert s.production and s.engine_url == "https://ave.example"


@pytest.mark.parametrize("override", [
    dict(ACCOUNTS_SECRET=""), dict(ACCOUNTS_SECRET="court"), dict(ACCOUNTS_ENGINE_URL="http://ave.example"),
    dict(ACCOUNTS_ENGINE_URL=""), dict(ACCOUNTS_ENGINE_KEY=""), dict(ACCOUNTS_OTP_SENDER="console"),
    dict(ACCOUNTS_OTP_WEBHOOK_URL=""), dict(ACCOUNTS_OTP_SENDER="pigeon"),
], ids=["sans-secret", "secret-court", "moteur-http", "sans-moteur", "sans-cle", "console", "sans-webhook", "inconnu"])
def test_production_config_refuses_unsafe_setups(override):
    with pytest.raises(ConfigError):
        Settings.from_env({**OK, **override})


PREVIEW = dict(ACCOUNTS_ENV="preview", ACCOUNTS_SECRET="x" * 40, ACCOUNTS_OTP_SENDER="webhook",
               ACCOUNTS_OTP_WEBHOOK_URL="https://sms.example/send")


def test_preview_starts_without_engine():
    s = Settings.from_env(dict(PREVIEW))
    assert s.hosted and not s.production and s.engine_url is None


@pytest.mark.parametrize("override", [
    dict(ACCOUNTS_SECRET=""), dict(ACCOUNTS_OTP_SENDER="console"),
    dict(ACCOUNTS_ENGINE_URL="http://ave.example", ACCOUNTS_ENGINE_KEY="cle"),
    dict(ACCOUNTS_ENGINE_URL="https://ave.example"), dict(ACCOUNTS_ENGINE_KEY="cle"),
], ids=["sans-secret", "console", "moteur-http", "url-sans-cle", "cle-sans-url"])
def test_preview_keeps_production_safeguards(override):
    # Pas de secret éphémère hors développement : il romprait tous les comptes au premier redémarrage.
    with pytest.raises(ConfigError):
        Settings.from_env({**PREVIEW, **override})


def test_missing_apple_key_file(tmp_path):
    missing = str(tmp_path / "absent.p8")
    apple = dict(ACCOUNTS_APPLE_AUDIENCE="com.tam.ave", ACCOUNTS_APPLE_TEAM_ID="TEAM", ACCOUNTS_APPLE_KEY_ID="KEY",
                 ACCOUNTS_APPLE_PRIVATE_KEY_FILE=missing)
    # Préproduction : démarre, sans révocation possible.
    assert not Settings.from_env({**PREVIEW, **apple}).apple_revocation_ready
    # Production : refus clair (révocation exigée par l'App Store), pas un plantage sur le fichier.
    with pytest.raises(ConfigError, match="révocation"):
        Settings.from_env({**OK, **apple})


def test_unknown_environment_is_refused():
    with pytest.raises(ConfigError):
        Settings.from_env({**PREVIEW, "ACCOUNTS_ENV": "prod"})


def test_dev_gets_an_ephemeral_secret_but_a_short_explicit_one_is_refused():
    s = Settings.from_env({})
    assert len(s.secret) >= 32 and not s.production
    with pytest.raises(ConfigError):
        Settings.from_env({"ACCOUNTS_SECRET": "court"})


def test_rate_limit_window(tmp_path):
    db = Database(str(tmp_path / "r.db"))
    with db.connect() as c:
        assert [ratelimit.hit(c, "k", 2, 60) for _ in range(2)] == [None, None]
        wait = ratelimit.hit(c, "k", 2, 60)
        assert wait is not None and 1 <= wait <= 60
        assert ratelimit.hit(c, "autre", 2, 60) is None


def test_pasted_values_are_trimmed_and_blank_counts_as_absent():
    # Copier-coller depuis un autre service : retour à la ligne en fin de valeur, champ laissé avec un espace.
    s = Settings.from_env({**PREVIEW, "ACCOUNTS_OTP_SENDER": "providers", "ACCOUNTS_INFOBIP_BASE_URL": "https://x.api.infobip.com\n",
                           "ACCOUNTS_INFOBIP_API_KEY": "  cle-infobip  ", "ACCOUNTS_ORANGE_AUTH_HEADER": "   "})
    assert s.infobip_base_url == "https://x.api.infobip.com" and s.infobip_api_key == "cle-infobip"
    assert s.orange_auth_header is None and not s.orange_ready


def test_missing_provider_error_names_variables_but_never_values():
    env = {**PREVIEW, "ACCOUNTS_OTP_SENDER": "providers", "ACCOUNTS_INFOBIP_API_KEY": "valeur-secrete-infobip"}
    with pytest.raises(ConfigError) as err:
        Settings.from_env(env)
    message = str(err.value)
    assert "ACCOUNTS_INFOBIP_API_KEY présente" in message and "ACCOUNTS_INFOBIP_BASE_URL absente" in message
    assert "valeur-secrete-infobip" not in message


def test_test_phones_accept_numbers_written_without_plus():
    s = Settings.from_env({**PREVIEW, "ACCOUNTS_OTP_TEST_PHONES": "224612141424, +224 627 222 121", "ACCOUNTS_OTP_TEST_CODE": "482917"})
    assert s.otp_test_phones == ("+224612141424", "+224627222121")
