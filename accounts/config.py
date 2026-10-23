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
    otp_sender: str = "console"                # console (dev) | webhook | providers
    otp_webhook_url: str | None = None
    otp_webhook_key: str | None = None
    # providers : WhatsApp Cloud API (Meta), puis SMS dans l'ordre de `sms_providers` (orange, infobip)
    whatsapp_token: str | None = None
    whatsapp_phone_number_id: str | None = None
    whatsapp_template: str = "ave_otp"
    whatsapp_language: str = "fr"
    whatsapp_api_version: str = "v21.0"
    sms_providers: tuple[str, ...] = ("orange", "infobip")
    orange_client_id: str | None = None
    orange_client_secret: str | None = None
    orange_sender_number: str = "2240000"      # Guinée (Orange Developer) ; autre pays : son numéro d'expéditeur
    orange_sender_name: str | None = None
    infobip_base_url: str | None = None
    infobip_api_key: str | None = None
    infobip_sender: str = "AVE"
    # Numéros de test à code fixe (revue Apple, essais) : AUCUN par défaut. Ces numéros ne reçoivent jamais de message.
    otp_test_phones: tuple[str, ...] = ()
    otp_test_code: str | None = None
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
                raise ConfigError("production : l'envoi des codes par la console est interdit "
                                  "(ACCOUNTS_OTP_SENDER=providers ou webhook)")
        if self.otp_sender == "webhook" and not self.otp_webhook_url:
            raise ConfigError("ACCOUNTS_OTP_WEBHOOK_URL manquant")
        if self.otp_sender not in ("console", "webhook", "providers"):
            raise ConfigError("ACCOUNTS_OTP_SENDER : console, webhook ou providers")
        if self.otp_sender == "providers":
            if not (self.whatsapp_ready or self.orange_ready or self.infobip_ready):
                raise ConfigError("ACCOUNTS_OTP_SENDER=providers : configurer au moins WhatsApp, Orange ou Infobip")
            unknown = [p for p in self.sms_providers if p not in ("orange", "infobip")]
            if unknown:
                raise ConfigError(f"ACCOUNTS_SMS_PROVIDERS : fournisseur inconnu {unknown}")
        if self.otp_test_phones:
            # Un code de test devinable ouvrirait ces comptes à n'importe qui : 6 chiffres, jamais un code évident.
            if not (self.otp_test_code and len(self.otp_test_code) == 6 and self.otp_test_code.isdigit()):
                raise ConfigError("ACCOUNTS_OTP_TEST_CODE (6 chiffres) obligatoire avec ACCOUNTS_OTP_TEST_PHONES")
            if self.otp_test_code in ("000000", "123456", "111111", "654321"):
                raise ConfigError("ACCOUNTS_OTP_TEST_CODE trop facile à deviner")
        return self

    @property
    def whatsapp_ready(self) -> bool:
        return bool(self.whatsapp_token and self.whatsapp_phone_number_id)

    @property
    def orange_ready(self) -> bool:
        return bool(self.orange_client_id and self.orange_client_secret)

    @property
    def infobip_ready(self) -> bool:
        return bool(self.infobip_base_url and self.infobip_api_key)

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
            whatsapp_token=g("ACCOUNTS_WHATSAPP_TOKEN"), whatsapp_phone_number_id=g("ACCOUNTS_WHATSAPP_PHONE_NUMBER_ID"),
            whatsapp_template=g("ACCOUNTS_WHATSAPP_TEMPLATE", "ave_otp"),
            whatsapp_language=g("ACCOUNTS_WHATSAPP_LANGUAGE", "fr"),
            whatsapp_api_version=g("ACCOUNTS_WHATSAPP_API_VERSION", "v21.0"),
            sms_providers=tuple(x.strip() for x in g("ACCOUNTS_SMS_PROVIDERS", "orange,infobip").split(",") if x.strip()),
            orange_client_id=g("ACCOUNTS_ORANGE_CLIENT_ID"), orange_client_secret=g("ACCOUNTS_ORANGE_CLIENT_SECRET"),
            orange_sender_number=g("ACCOUNTS_ORANGE_SENDER_NUMBER", "2240000"),
            orange_sender_name=g("ACCOUNTS_ORANGE_SENDER_NAME") or None,
            infobip_base_url=g("ACCOUNTS_INFOBIP_BASE_URL"), infobip_api_key=g("ACCOUNTS_INFOBIP_API_KEY"),
            infobip_sender=g("ACCOUNTS_INFOBIP_SENDER", "AVE"),
            otp_test_phones=tuple(x.strip() for x in g("ACCOUNTS_OTP_TEST_PHONES", "").split(",") if x.strip()),
            otp_test_code=g("ACCOUNTS_OTP_TEST_CODE") or None,
            trust_proxy=g("ACCOUNTS_TRUST_PROXY") == "1",
        ).validate()
