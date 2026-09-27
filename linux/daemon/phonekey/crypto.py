"""ECDSA P-256 / SHA-256 helpers (protocol/PROTOCOL.md §2). Standard primitives only."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Domain-separation labels; a signature under one label is never valid under another.
LABEL_PAIR_REQUEST = b"PhoneKey/v1/pair-request\0"
LABEL_PAIR_RESPONSE = b"PhoneKey/v1/pair-response\0"
LABEL_AUTH_REQUEST = b"PhoneKey/v1/auth-request\0"
LABEL_AUTH_ASSERTION = b"PhoneKey/v1/auth-assertion\0"

SPKI_SIZE = 91

PrivateKey = ec.EllipticCurvePrivateKey
PublicKey = ec.EllipticCurvePublicKey


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def key_id(spki: bytes) -> bytes:
    """device_id / verifier_id: SHA-256 of the DER SubjectPublicKeyInfo."""
    return sha256(spki)


def spki_of(key: PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_key(spki: bytes) -> PublicKey:
    """Parses a P-256 SubjectPublicKeyInfo; rejects other curves and non-canonical encodings."""
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError) as e:
        raise ValueError("invalid SubjectPublicKeyInfo") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("not a P-256 public key")
    if spki_of(key) != spki:
        raise ValueError("non-canonical public key encoding")
    return key


def generate_key() -> PrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def sign(key: PrivateKey, label: bytes, data: bytes) -> bytes:
    return key.sign(label + data, ec.ECDSA(hashes.SHA256()))


def verify(key: PublicKey, label: bytes, data: bytes, signature: bytes) -> bool:
    try:
        key.verify(signature, label + data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def load_or_create_key(path: Path) -> PrivateKey:
    """Loads the verifier key, or creates it (mode 0600, never overwriting)."""
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(f"{path} is not a P-256 private key")
        return key
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = generate_key()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),  # protected by file permissions, like SSH host keys
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key
