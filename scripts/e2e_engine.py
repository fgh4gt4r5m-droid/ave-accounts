"""Essai de bout en bout : service de comptes <-> VRAI moteur AVE (multiplateforme, Python seul).

    python scripts/e2e_engine.py --engine-dir ../african-voice-engine

Prérequis : un clone du moteur sur une branche qui contient `DELETE /v1/subjects/{sub}/learning` (endpoints-sujets ou plus récent),
`pip install -e .[dev] websockets fastapi uvicorn` (les dépendances du moteur : voir son pyproject). Le script :
crée un tenant « ave-grand-public » avec learning:"opt_in" (tools/make_key.py du moteur), lance le moteur et le service sur des ports libres,
capte le code reçu par un faux webhook SMS, puis vérifie : connexion par code, jeton court accepté par le moteur, jeton inventé refusé,
consentement conservé d'une session à l'autre, suppression de compte qui efface les données côté moteur. Aucun secret n'est écrit hors du dossier temporaire.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import websockets

ROOT = Path(__file__).resolve().parent.parent
results: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    results.append((ok, label))
    print(("  OK  " if ok else "  ÉCHEC ") + label, flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 20) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise SystemExit(f"service injoignable : {url}")


class SMSCatcher(BaseHTTPRequestHandler):
    """Faux fournisseur SMS : reçoit le POST du WebhookOTPSender et en garde le code."""
    codes: list[str] = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        m = re.search(r"\b(\d{6})\b", body["message"])
        SMSCatcher.codes.append(m.group(1) if m else "")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):  # silencieux
        pass


async def ws_session(engine: str, token: str, consent: bool = False):
    async with websockets.connect(engine.replace("http", "ws") + "/v1/stream") as ws:
        await ws.send(json.dumps({"type": "hello", "version": 1, "codec": "pcm16", "lang": "fra", "sample_rate": 16000,
                                  "vad": "client", "token": token}))
        ready = json.loads(await asyncio.wait_for(ws.recv(), 5))
        state = None
        if ready.get("type") == "ready" and consent and ready.get("learning", {}).get("available"):
            await ws.send(json.dumps({"type": "learning_consent", "granted": True, "version": ready["learning"]["notice_version"]}))
            await ws.send(json.dumps({"type": "text", "text": "bonjour AVE, ceci est un essai"}))
            while True:
                raw = await asyncio.wait_for(ws.recv(), 10)
                if isinstance(raw, bytes):
                    continue
                m = json.loads(raw)
                if m["type"] == "learning_state":
                    state = m
                if m["type"] == "turn_end":
                    break
        return ready, state


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine-dir", required=True, help="clone du moteur (african-voice-engine)")
    a = ap.parse_args()
    engine_dir = Path(a.engine_dir).resolve()
    tmp = Path(tempfile.mkdtemp(prefix="ave-e2e-"))
    procs: list[subprocess.Popen] = []
    try:
        out = subprocess.run([sys.executable, "tools/make_key.py", "ave-grand-public", "customer_service", "--langs", "fra",
                              "--learning", "opt_in"], cwd=engine_dir, capture_output=True, text=True, check=True).stdout
        b2b_key = re.search(r"jeton client : (\S+)", out).group(1)
        (tmp / "tenants.json").write_text(out[out.index("{"):])
        (tmp / "learn").mkdir()

        sms = HTTPServer(("127.0.0.1", 0), SMSCatcher)
        threading.Thread(target=sms.serve_forever, daemon=True).start()
        engine_port, acc_port = free_port(), free_port()
        engine, acc = f"http://127.0.0.1:{engine_port}", f"http://127.0.0.1:{acc_port}"

        env = dict(os.environ, AVE_TENANTS_FILE=str(tmp / "tenants.json"), AVE_TOKEN_SECRET="t" * 40,
                   AVE_LEARNING_DIR=str(tmp / "learn"), AVE_PORT=str(engine_port))
        procs.append(subprocess.Popen([sys.executable, "-m", "ave"], cwd=engine_dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        env2 = dict(os.environ, ACCOUNTS_ENV="dev", ACCOUNTS_SECRET="a" * 48, ACCOUNTS_DB=str(tmp / "accounts.db"), ACCOUNTS_PORT=str(acc_port),
                    ACCOUNTS_ENGINE_URL=engine, ACCOUNTS_ENGINE_KEY=b2b_key, ACCOUNTS_OTP_SENDER="webhook",
                    ACCOUNTS_OTP_WEBHOOK_URL=f"http://127.0.0.1:{sms.server_port}/sms", ACCOUNTS_OTP_WEBHOOK_KEY="x")
        procs.append(subprocess.Popen([sys.executable, "-m", "accounts"], cwd=ROOT, env=env2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_http(engine + "/healthz")
        wait_http(acc + "/healthz")

        print("Connexion par téléphone et jetons")
        phone = "+22462" + str(int(time.time()) % 10_000_000).zfill(7)
        with httpx.Client(timeout=10) as c:
            r = c.post(acc + "/auth/otp/request", json={"phone": phone, "channel": "whatsapp"})
            check(r.status_code == 200 and len(SMSCatcher.codes) == 1, "code envoyé par le webhook")
            v = c.post(acc + "/auth/otp/verify", json={"challenge_id": r.json()["challenge_id"], "code": SMSCatcher.codes[0]})
            check(v.status_code == 200, "code accepté, jeton long reçu")
            refresh = v.json()["refresh_token"]
            auth = {"Authorization": "Bearer " + refresh}
            tok = c.post(acc + "/auth/token", headers=auth).json()["token"]
            check(tok.startswith("t1."), "jeton court délivré via le moteur")

            print("Le moteur accepte le jeton et applique le consentement")
            ready, state = asyncio.run(ws_session(engine, tok, consent=True))
            check(ready.get("type") == "ready", "jeton court accepté par le moteur (ready)")
            check(ready.get("learning", {}).get("available") is True, "apprentissage proposé (tenant opt_in + sub)")
            check(bool(state) and state["enabled"] is True, "consentement enregistré (learning_state granted)")
            ready_bad, _ = asyncio.run(ws_session(engine, "t1.jeton-invente"))
            check(ready_bad.get("code") == "unauthorized", "jeton inventé refusé (unauthorized)")

            tok2 = c.post(acc + "/auth/token", headers=auth).json()["token"]
            ready2, _ = asyncio.run(ws_session(engine, tok2))
            check(ready2["learning"]["enabled"] is True, "consentement conservé dans la session suivante (même compte)")
            files = [p for p in (tmp / "learn").rglob("*") if p.is_file() and p.name != "consents.jsonl"]
            check(len(files) >= 1, f"données collectées côté moteur ({len(files)} fichier)")

            print("Suppression du compte")
            d = c.delete(acc + "/account", headers=auth)
            check(d.status_code == 204, "DELETE /account accepté")
            files_after = [p for p in (tmp / "learn").rglob("*") if p.is_file() and p.name != "consents.jsonl"]
            check(files_after == [], "données d'apprentissage effacées côté moteur")
            check(c.post(acc + "/auth/token", headers=auth).status_code == 401, "jeton long refusé après suppression")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} vérifications réussies")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
