"""Fenêtre glissante dans la base : fonctionne avec plusieurs processus, sans état en mémoire."""
from __future__ import annotations

from .db import now


def hit(db, key: str, limit: int, window_s: int) -> int | None:
    """Enregistre un événement. Renvoie None s'il passe, sinon le délai (s) avant de pouvoir réessayer."""
    t = now()
    rows = db.execute("SELECT ts FROM rate_events WHERE key=? AND ts>? ORDER BY ts", (key, t - window_s)).fetchall()
    if len(rows) >= limit:
        return max(1, rows[len(rows) - limit]["ts"] + window_s - t)
    db.execute("INSERT INTO rate_events(key, ts) VALUES(?,?)", (key, t))
    return None


def purge(db, older_than_s: int = 86_400) -> None:
    db.execute("DELETE FROM rate_events WHERE ts<?", (now() - older_than_s,))
    db.execute("DELETE FROM otp_challenges WHERE expires_at<?", (now() - 3600,))
    db.execute("DELETE FROM guest_challenges WHERE expires_at<?", (now(),))
