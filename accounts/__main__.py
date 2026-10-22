"""`python3 -m accounts` : lance le service (configuration par variables d'environnement, voir README.md)."""
import logging
import os

import uvicorn

from .api import build_services, create_app
from .config import Settings

logging.basicConfig(level=logging.INFO)
app = create_app(build_services(Settings.from_env()))

if __name__ == "__main__":
    uvicorn.run(app, host=os.getenv("ACCOUNTS_HOST", "127.0.0.1"), port=int(os.getenv("ACCOUNTS_PORT", "8790")))
