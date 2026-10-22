"""Client du moteur AVE avec la clé B2B du tenant « AVE grand public » (cette clé reste ICI, sur le serveur) :
`POST /v1/token` (jeton court) et `DELETE /v1/subjects/{sub}/learning` (effacement des données d'apprentissage d'un sujet)."""
from __future__ import annotations

import time

import httpx


class EngineUnavailable(Exception):
    def __init__(self, message: str, retry_after_s: int | None = None):
        super().__init__(message)
        self.retry_after_s = retry_after_s


class EngineTokenClient:
    # Le moteur limite /v1/token et /v1/subjects (30 d'avance puis 1/s, 429 + Retry-After). On réessaie au plus
    # `max_retries` fois, seulement si l'attente demandée est courte : on ne boucle jamais et on ne bloque pas une requête.
    MAX_WAIT_S = 3

    def __init__(self, base_url: str, api_key: str, client: httpx.Client | None = None, sleep=time.sleep, max_retries: int = 2):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=10)
        self.sleep = sleep
        self.max_retries = max_retries

    def _call(self, method: str, path: str, json: dict | None = None) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        for attempt in range(self.max_retries + 1):
            try:
                r = self.client.request(method, f"{self.base_url}{path}", json=json, headers=headers)
            except httpx.HTTPError as e:
                raise EngineUnavailable(type(e).__name__) from e
            if r.status_code != 429:
                return r
            wait = _retry_after(r)
            if attempt == self.max_retries or wait > self.MAX_WAIT_S:
                raise EngineUnavailable("HTTP 429", retry_after_s=wait)
            self.sleep(wait)
        raise EngineUnavailable("HTTP 429")  # inatteignable : la boucle lève ou retourne

    def mint(self, ttl_s: int, sub: str | None = None, languages: list[str] | None = None) -> tuple[str, int]:
        body: dict = {"ttl_s": ttl_s}
        if sub:
            body["sub"] = sub          # absent pour un invité : pas d'identifiant stable, pas d'apprentissage persistant
        if languages:
            body["languages"] = languages
        r = self._call("POST", "/v1/token", body)
        if r.status_code != 200:
            raise EngineUnavailable(f"HTTP {r.status_code}")  # 401 = clé B2B invalide : ne jamais la répercuter au client
        data = r.json()
        return data["token"], int(data["expires_in"])

    def erase_subject_learning(self, sub: str) -> int:
        """Retire le consentement ET efface ce qui a été collecté pour ce sujet (ce tenant seulement). Idempotent.
        Renvoie le nombre d'éléments effacés. Collecte non configurée côté moteur (503 `learning_disabled`) : rien n'a pu être collecté, 0."""
        r = self._call("DELETE", f"/v1/subjects/{sub}/learning")
        if r.status_code == 200:
            return int(r.json().get("deleted", 0))
        if r.status_code == 503 and _error(r) == "learning_disabled":
            return 0
        raise EngineUnavailable(f"HTTP {r.status_code}")


def _retry_after(r: httpx.Response) -> int:
    try:
        return max(1, int(r.json().get("retry_after_s") or r.headers.get("Retry-After") or 1))
    except (ValueError, TypeError, AttributeError):
        return 1


def _error(r: httpx.Response) -> str | None:
    try:
        return r.json().get("error")
    except ValueError:
        return None
