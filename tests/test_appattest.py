"""Vérifie la LOGIQUE avec une chaîne de certificats synthétique (racine, intermédiaire, feuille). Ce n'est pas une preuve de
compatibilité avec une vraie attestation Apple."""
import base64
import datetime as dt
import hashlib

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from accounts.appattest import AAGUID_DEVELOPMENT, AAGUID_PRODUCTION, OID_NONCE, AppAttestVerifier
from accounts.errors import AccountsError

APP_ID = "TEAM123456.fr.ave.app"
NOW = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)


def der(tag: int, content: bytes) -> bytes:
    assert len(content) < 128
    return bytes([tag, len(content)]) + content


def make_cert(cn, pub, issuer_cn, issuer_key, ext=None, ca=False, not_before=None, not_after=None):
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(not_before or NOW - dt.timedelta(days=1)).not_valid_after(not_after or NOW + dt.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(OID_NONCE, ext), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


class Chain:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.root = make_cert("Fake Root", self.root_key.public_key(), "Fake Root", self.root_key, ca=True)
        self.inter = make_cert("Fake Inter", self.inter_key.public_key(), "Fake Root", self.root_key, ca=True)
        point = self.device_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.key_hash = hashlib.sha256(point).digest()
        self.key_id = base64.b64encode(self.key_hash).decode()

    @property
    def root_pem(self):
        return self.root.public_bytes(serialization.Encoding.PEM)

    def attest(self, challenge: bytes, *, app_id=APP_ID, counter=0, aaguid=AAGUID_PRODUCTION, cid=None, nonce_override=None,
               fmt="apple-appattest", cred_not_after=None, inter_key=None) -> bytes:
        auth = (hashlib.sha256(app_id.encode()).digest() + b"\x40" + counter.to_bytes(4, "big") + aaguid
                + (32).to_bytes(2, "big") + (cid or self.key_hash))
        nonce = nonce_override or hashlib.sha256(auth + hashlib.sha256(challenge).digest()).digest()
        ext = der(0x30, der(0xA1, der(0x04, nonce)))
        cred = make_cert("cred", self.device_key.public_key(), "Fake Inter", inter_key or self.inter_key, ext=ext,
                         not_after=cred_not_after)
        return cbor2.dumps({"fmt": fmt, "attStmt": {"x5c": [cred.public_bytes(serialization.Encoding.DER),
                                                           self.inter.public_bytes(serialization.Encoding.DER)], "receipt": b""},
                            "authData": auth})


@pytest.fixture
def chain():
    return Chain()


def verifier(chain, **kw):
    return AppAttestVerifier(kw.pop("app_id", APP_ID), kw.pop("root_pem", chain.root_pem), clock=lambda: NOW, **kw)


def rejects(v, key_id, att, challenge):
    with pytest.raises(AccountsError) as e:
        v.verify(key_id, att, challenge)
    assert (e.value.status, e.value.code) == (401, "rejected")


def test_valid_attestation_passes(chain):
    ch = b"defi-serveur-32-octets-exactement!"
    verifier(chain).verify(chain.key_id, chain.attest(ch), ch)


def test_wrong_challenge_is_rejected(chain):
    rejects(verifier(chain), chain.key_id, chain.attest(b"defi-A"), b"defi-B")


def test_wrong_app_id_is_rejected(chain):
    rejects(verifier(chain, app_id="TEAM123456.autre.app"), chain.key_id, chain.attest(b"c"), b"c")


def test_counter_must_be_zero(chain):
    rejects(verifier(chain), chain.key_id, chain.attest(b"c", counter=1), b"c")


def test_aaguid_development_only_when_enabled(chain):
    att = chain.attest(b"c", aaguid=AAGUID_DEVELOPMENT)
    rejects(verifier(chain), chain.key_id, att, b"c")
    verifier(chain, development=True).verify(chain.key_id, att, b"c")
    rejects(verifier(chain, development=True), chain.key_id, chain.attest(b"c", aaguid=b"autre-aaguid-xxx"), b"c")


def test_key_id_must_match_the_certificate_key(chain):
    other = base64.b64encode(hashlib.sha256(b"autre cle").digest()).decode()
    rejects(verifier(chain), other, chain.attest(b"c"), b"c")
    rejects(verifier(chain), "pas du base64 !!", chain.attest(b"c"), b"c")


def test_credential_id_must_match(chain):
    rejects(verifier(chain), chain.key_id, chain.attest(b"c", cid=b"\x01" * 32), b"c")


def test_tampered_nonce_is_rejected(chain):
    rejects(verifier(chain), chain.key_id, chain.attest(b"c", nonce_override=b"\x00" * 32), b"c")


def test_untrusted_root_is_rejected(chain):
    stranger = Chain()
    rejects(verifier(chain, root_pem=stranger.root_pem), chain.key_id, chain.attest(b"c"), b"c")


def test_leaf_not_signed_by_the_intermediate_is_rejected(chain):
    rejects(verifier(chain), chain.key_id, chain.attest(b"c", inter_key=ec.generate_private_key(ec.SECP256R1())), b"c")


def test_expired_certificate_is_rejected(chain):
    att = chain.attest(b"c", cred_not_after=NOW - dt.timedelta(hours=1))
    rejects(verifier(chain), chain.key_id, att, b"c")


def test_wrong_format_and_garbage_are_rejected(chain):
    rejects(verifier(chain), chain.key_id, chain.attest(b"c", fmt="packed"), b"c")
    rejects(verifier(chain), chain.key_id, b"pas du CBOR", b"c")
    rejects(verifier(chain), chain.key_id, cbor2.dumps({"fmt": "apple-appattest"}), b"c")
    rejects(verifier(chain), chain.key_id, b"", b"c")
