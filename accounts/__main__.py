"""`python3 -m accounts` : lance le service (configuration par variables d'environnement, voir README.md)."""
import logging
import os

import uvicorn

from .api import build_services, create_app
from .config import Settings

logging.basicConfig(level=logging.INFO)
app = create_app(build_services(Settings.from_env()))

if __name__ == "__main__":
    # Render (et la plupart des hébergeurs) imposent le port par $PORT ; ACCOUNTS_PORT reste prioritaire en local.
    port = int(os.getenv("ACCOUNTS_PORT") or os.getenv("PORT") or "8790")
    # `proxy_headers` : derrière le proxy de Render, l'IP réelle vient de X-Forwarded-For (voir ACCOUNTS_TRUST_PROXY).
    uvicorn.run(app, host=os.getenv("ACCOUNTS_HOST", "127.0.0.1"), port=port, proxy_headers=True)
