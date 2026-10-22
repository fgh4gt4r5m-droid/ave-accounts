"""Vérification d'une attestation App Attest (invité) selon la procédure documentée par Apple :
1. objet CBOR `apple-appattest` ; 2. chaîne x5c (certificat feuille → intermédiaire → RACINE APPLE fournie par la configuration) ;
3. nonce = SHA256(authData ‖ SHA256(challenge)) retrouvé dans l'extension 1.2.840.113635.100.8.2 ;
4. SHA256(clé publique de la feuille) = identifiant de clé ; 5. authData : rpIdHash = SHA256(app id), compteur = 0, AAGUID, credentialId.

⚠ Testé avec une chaîne de certificats SYNTHÉTIQUE (voir tests/test_appattest.py), PAS avec une vraie attestation Apple :
à valider sur un appareil réel avec le vrai certificat racine avant d'ouvrir le mode invité.
Limite : une clé d'appareil ne s'atteste qu'une fois ; l'app en crée une neuve à chaque essai → la protection contre les comptes
invités fabriqués en masse repose sur la limitation de débit par IP et sur les quotas, pas sur l'unicité de l'appareil."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from .errors import rejected

OID_NONCE = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"


def _der(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = buf[pos]
    n = buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    return tag, buf[pos:pos + n], pos + n


def _nonce_from_extension(value: bytes) -> bytes:
    """SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } }"""
    tag, seq, _ = _der(value, 0)
    if tag != 0x30:
        raise ValueError("séquence attendue")
    tag, ctx, _ = _der(seq, 0)
    if tag != 0xA1:
        raise ValueError("[1] attendu")
    tag, octets, _ = _der(ctx, 0)
    if tag != 0x04:
        raise ValueError("OCTET STRING attendu")
    return octets


def _signed_by(child: x509.Certificate, parent: x509.Certificate) -> None:
    key = parent.public_key()
    if child.issuer != parent.subject:
        raise ValueError("émetteur différent")
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
    else:
        key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)


class AppAttestVerifier:
    def __init__(self, app_id: str, root_pem: bytes, development: bool = False, clock=None):
        self.rp_hash = hashlib.sha256(app_id.encode()).digest()
        self.root = x509.load_pem_x509_certificate(root_pem)
        self.aaguids = {AAGUID_PRODUCTION} | ({AAGUID_DEVELOPMENT} if development else set())
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def verify(self, key_id_b64: str, attestation: bytes, challenge: bytes) -> None:
        """Lève `rejected` si l'attestation n'est pas valable pour CE défi et CETTE clé."""
        try:
            self._verify(key_id_b64, attestation, challenge)
        except (ValueError, KeyError, TypeError, IndexError, InvalidSignature, cbor2.CBORDecodeError, x509.ExtensionNotFound):
            raise rejected() from None

    def _verify(self, key_id_b64: str, attestation: bytes, challenge: bytes) -> None:
        obj = cbor2.loads(attestation)
        if obj["fmt"] != "apple-appattest":
            raise ValueError("format")
        auth: bytes = obj["authData"]
        x5c = obj["attStmt"]["x5c"]
        cred = x509.load_der_x509_certificate(x5c[0])
        inter = x509.load_der_x509_certificate(x5c[1])

        now = self.clock()
        for cert in (cred, inter, self.root):
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                raise ValueError("certificat hors validité")
        _signed_by(cred, inter)
        _signed_by(inter, self.root)

        nonce = hashlib.sha256(auth + hashlib.sha256(challenge).digest()).digest()
        ext = cred.extensions.get_extension_for_oid(OID_NONCE).value
        if _nonce_from_extension(ext.value) != nonce:
            raise ValueError("nonce")

        point = cred.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        key_hash = hashlib.sha256(point).digest()
        if key_hash != base64.b64decode(key_id_b64, validate=True):
            raise ValueError("identifiant de clé")

        if auth[0:32] != self.rp_hash:
            raise ValueError("rpIdHash")
        if int.from_bytes(auth[33:37], "big") != 0:
            raise ValueError("compteur")
        if auth[37:53] not in self.aaguids:
            raise ValueError("aaguid")
        cid_len = int.from_bytes(auth[53:55], "big")
        if auth[55:55 + cid_len] != key_hash:
            raise ValueError("credentialId")
