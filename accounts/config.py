"""Configuration par variables d'environnement. AUCUN secret par défaut en production (comme le moteur)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    env: str = "dev"                          # dev | production
    db_path: str = "accounts.db"
    secret: bytes = b""                        # HMAC (pseudonymes, empreintes, codes) : >= 32 octets
    engine_url: str | None = None              # https://… du moteur AVE
    engine_key: str | None = None              # clé B2B du tenant « AVE grand public » : JAMAIS dans le dépôt
    token_ttl_s: int = 600
    token_languages: tuple[str, ...] = ()      # restreint les langues du jeton (vide = celles du tenant)
    apple_audience: str | None = None          # identifiant de l'app (bundle id) attendu dans le jeton Apple
    appattest_app_id: str | None = None        # « <TEAM_ID>.<BUNDLE_ID> »
    appattest_root_pem: bytes | None = None    # certificat racine « Apple App Attestation Root CA »
    appattest_development: bool = False        # accepte l'AAGUID de développement
    otp_sender: str = "console"                # console (dev) | webhook
    otp_webhook_url: str | None = None
    otp_webhook_key: str | None = None
    otp_ttl_s: int = 300
    otp_max_attempts: int = 5
    otp_resend_s: int = 30
    refresh_ttl_days: int = 90
    guest_refresh_ttl_days: int = 30
    account_tokens_per_day: int = 500
    guest_tokens_per_day: int = 30
    trust_proxy: bool = False                  # lire l'IP dans X-Forwarded-For (derrière un reverse proxy de confiance)
    ip_otp_per_hour: int = 20
    phone_otp_per_hour: int = 5
    ip_guest_per_hour: int = 10
    extra: dict = field(default_factory=dict)

    @property
    def production(self) -> bool:
        return self.env == "production"

    def validate(self) -> "Settings":
        if len(self.secret) < 32:
            raise ConfigError("ACCOUNTS_SECRET (>= 32 caractères) est obligatoire : aucun secret par défaut")
        if self.production:
            if not (self.engine_url and self.engine_url.startswith("https://")):
                raise ConfigError("production : ACCOUNTS_ENGINE_URL en https:// obligatoire")
            if not self.engine_key:
                raise ConfigError("production : ACCOUNTS_ENGINE_KEY obligatoire")
            if self.otp_sender == "console":
                raise ConfigError("production : l'envoi des codes par la console est interdit (ACCOUNTS_OTP_SENDER=webhook)")
        if self.otp_sender == "webhook" and not self.otp_webhook_url:
            raise ConfigError("ACCOUNTS_OTP_WEBHOOK_URL manquant")
        if self.otp_sender not in ("console", "webhook"):
            raise ConfigError("ACCOUNTS_OTP_SENDER : console ou webhook")
        return self

    @classmethod
    def from_env(cls, environ=os.environ) -> "Settings":
        g = environ.get
        env = g("ACCOUNTS_ENV", "dev")
        secret = g("ACCOUNTS_SECRET")
        if not secret and env != "production":
            secret = secrets.token_urlsafe(48)  # dev : éphémère, les jetons ne survivent pas à un redémarrage
        root = g("ACCOUNTS_APPATTEST_ROOT_PEM")
        return cls(
            env=env, db_path=g("ACCOUNTS_DB", "accounts.db"), secret=(secret or "").encode(),
            engine_url=(g("ACCOUNTS_ENGINE_URL") or None) and g("ACCOUNTS_ENGINE_URL").rstrip("/"),
            engine_key=g("ACCOUNTS_ENGINE_KEY"), token_ttl_s=int(g("ACCOUNTS_TOKEN_TTL_S", "600")),
            token_languages=tuple(x for x in g("ACCOUNTS_TOKEN_LANGUAGES", "").split(",") if x),
            apple_audience=g("ACCOUNTS_APPLE_AUDIENCE"), appattest_app_id=g("ACCOUNTS_APPATTEST_APP_ID"),
            appattest_root_pem=Path(root).read_bytes() if root else None,
            appattest_development=g("ACCOUNTS_APPATTEST_DEVELOPMENT") == "1",
            otp_sender=g("ACCOUNTS_OTP_SENDER", "console"), otp_webhook_url=g("ACCOUNTS_OTP_WEBHOOK_URL"),
            otp_webhook_key=g("ACCOUNTS_OTP_WEBHOOK_KEY"),
            trust_proxy=g("ACCOUNTS_TRUST_PROXY") == "1",
        ).validate()
