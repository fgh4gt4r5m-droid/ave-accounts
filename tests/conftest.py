import re

import pytest
from fastapi.testclient import TestClient

from accounts.api import create_app
from accounts.config import Settings
from accounts.db import Database
from accounts.engine import EngineUnavailable
from accounts.errors import rejected
from accounts.otp import OTPDeliveryError
from accounts.service import Services

SECRET = b"s" * 48
PHONE = "+224621234567"


class FakeOTP:
    def __init__(self):
        self.sent: list[tuple[str, str, str]] = []
        self.fail = False

    def send(self, phone, channel, code):
        if self.fail:
            raise OTPDeliveryError("down")
        self.sent.append((phone, channel, code))

    @property
    def last_code(self) -> str:
        return self.sent[-1][2]


class FakeEngine:
    def __init__(self):
        self.calls: list[dict] = []
        self.fail = False
        self.erased: list[str] = []
        self.erase_fail = False
        self.retry_after: int | None = None

    def mint(self, ttl_s, sub=None, languages=None):
        if self.fail:
            raise EngineUnavailable("HTTP 500", retry_after_s=self.retry_after)
        self.calls.append({"ttl_s": ttl_s, "sub": sub, "languages": languages})
        return f"t1.fake{len(self.calls)}", ttl_s


    def erase_subject_learning(self, sub):
        if self.erase_fail:
            raise EngineUnavailable("HTTP 500")
        self.erased.append(sub)
        return 2


class FakeAttest:
    """Accepte tout sauf la clé « bad »."""

    def verify(self, key_id, attestation, challenge):
        if key_id == "bad":
            raise rejected()


class Env:
    def __init__(self, tmp_path, **overrides):
        base = dict(secret=SECRET, db_path=str(tmp_path / "a.db"), resend=0)
        self.settings = Settings(
            secret=SECRET, db_path=str(tmp_path / "a.db"), otp_resend_s=overrides.pop("otp_resend_s", 0),
            **overrides)
        self.otp = FakeOTP()
        self.engine = FakeEngine()
        self.services = Services(self.settings, Database(self.settings.db_path), self.otp, self.engine)
        self.app = None

    def client(self, **extra) -> TestClient:
        for k, v in extra.items():
            setattr(self.services, k, v)
        self.app = create_app(self.services)
        return TestClient(self.app)

    def login(self, client: TestClient, phone: str = PHONE) -> str:
        r = client.post("/auth/otp/request", json={"phone": phone, "channel": "sms"})
        assert r.status_code == 200, r.text
        v = client.post("/auth/otp/verify", json={"challenge_id": r.json()["challenge_id"], "code": self.otp.last_code})
        assert v.status_code == 200, v.text
        return v.json()["refresh_token"]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
