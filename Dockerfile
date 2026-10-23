# Image du service de comptes AVE (déploiement Render, voir DEPLOIEMENT.md). Aucun secret dans l'image :
# tout passe par les variables d'environnement de l'hébergeur.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ACCOUNTS_HOST=0.0.0.0

WORKDIR /app
COPY pyproject.toml README.md ./
COPY accounts ./accounts
RUN pip install --no-cache-dir .

# Utilisateur sans privilèges ; /data est le disque persistant (base SQLite), monté par l'hébergeur.
RUN useradd --create-home --uid 10001 ave && mkdir -p /data && chown ave:ave /data
USER ave

EXPOSE 8790
CMD ["python", "-m", "accounts"]
