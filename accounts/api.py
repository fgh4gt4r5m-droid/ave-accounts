"""API HTTP (FastAPI) conforme à contrat/CONTRAT.md §6 (dépôt african-voice-engine)."""
from __future__ import annotations

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from .apple import AppleVerifier
from .appattest import AppAttestVerifier
from .config import Settings
from .db import Database
from .engine import EngineTokenClient
from .errors import AccountsError, unauthorized
from .otp import (ConsoleOTPSender, FallbackOTPSender, InfobipSMSSender, OrangeSMSSender, OTPSender, WebhookOTPSender,
                  WhatsAppCloudSender)
from .service import Accounts, Services


class OTPRequest(BaseModel):
    phone: str
    channel: str = "sms"


class OTPVerify(BaseModel):
    challenge_id: str
    code: str


class AppleBody(BaseModel):
    identity_token: str
    nonce: str


class GuestBody(BaseModel):
    key_id: str
    attestation: str
    challenge: str


def build_otp_sender(s: Settings) -> OTPSender:
    if s.otp_sender == "webhook":
        return WebhookOTPSender(s.otp_webhook_url or "", s.otp_webhook_key, s.otp_ttl_s)
    if s.otp_sender == "providers":
        whatsapp = (WhatsAppCloudSender(s.whatsapp_token or "", s.whatsapp_phone_number_id or "", s.whatsapp_template,
                                        s.whatsapp_language, s.whatsapp_api_version) if s.whatsapp_ready else None)
        available = {
            "orange": (OrangeSMSSender(s.orange_client_id, s.orange_client_secret, s.orange_sender_number,
                                       s.orange_sender_name, s.otp_ttl_s, auth_header=s.orange_auth_header)
                       if s.orange_ready else None),
            "infobip": (InfobipSMSSender(s.infobip_base_url or "", s.infobip_api_key or "", s.infobip_sender, s.otp_ttl_s)
                        if s.infobip_ready else None),
        }
        sms = [(name, sender) for name in s.sms_providers if (sender := available.get(name)) is not None]
        return FallbackOTPSender(whatsapp, sms)
    return ConsoleOTPSender(s.otp_ttl_s)


def build_services(settings: Settings) -> Services:
    otp = build_otp_sender(settings)
    engine = (EngineTokenClient(settings.engine_url, settings.engine_key)
              if settings.engine_url and settings.engine_key else None)
    apple = AppleVerifier(settings.apple_audience) if settings.apple_audience else None
    attest = (AppAttestVerifier(settings.appattest_app_id, settings.appattest_root_pem, settings.appattest_development)
              if settings.appattest_app_id and settings.appattest_root_pem else None)
    return Services(settings, Database(settings.db_path), otp, engine, apple, attest)


def create_app(services: Services) -> FastAPI:
    app = FastAPI(title="AVE accounts", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
    acc = Accounts(services)
    trust_proxy = services.settings.trust_proxy

    def client_ip(request: Request) -> str:
        if trust_proxy and (fwd := request.headers.get("x-forwarded-for")):
            return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def bearer(authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise unauthorized()
        token = authorization[7:].strip()
        if not token:
            raise unauthorized()
        return token

    @app.exception_handler(AccountsError)
    async def _accounts_error(_: Request, e: AccountsError):
        body: dict = {"error": e.code}
        headers = {}
        if e.retry_after_s is not None:
            body["retry_after_s"] = e.retry_after_s
            headers["Retry-After"] = str(e.retry_after_s)
        return JSONResponse(body, status_code=e.status, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def _bad_request(_: Request, __: RequestValidationError):
        return JSONResponse({"error": "bad_request"}, status_code=400)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/auth/otp/request")
    def otp_request(body: OTPRequest, request: Request):
        return acc.request_otp(body.phone, body.channel, client_ip(request))

    @app.post("/auth/otp/verify")
    def otp_verify(body: OTPVerify):
        return {"refresh_token": acc.verify_otp(body.challenge_id, body.code)}

    @app.post("/auth/apple")
    def apple(body: AppleBody):
        return {"refresh_token": acc.sign_in_apple(body.identity_token, body.nonce)}

    @app.post("/auth/guest/challenge")
    def guest_challenge(request: Request):
        return {"challenge": acc.guest_challenge(client_ip(request))}

    @app.post("/auth/guest")
    def guest(body: GuestBody, request: Request):
        return {"refresh_token": acc.sign_in_guest(body.key_id, body.attestation, body.challenge, client_ip(request))}

    @app.post("/auth/token")
    def token(authorization: str | None = Header(default=None)):
        return acc.access_token(bearer(authorization))

    @app.post("/auth/signout", status_code=204)
    def signout(authorization: str | None = Header(default=None)):
        acc.sign_out(bearer(authorization))
        return Response(status_code=204)

    @app.delete("/account", status_code=204)
    def delete_account(authorization: str | None = Header(default=None)):
        acc.delete_account(bearer(authorization))
        return Response(status_code=204)

    return app
