"""Android Keystore attestation summary — informational only (SECURITY.md D-5).

Nothing here ever affects pairing or authentication. The chain is not verified
against Google's attestation roots (that would need pinned roots and, for
revocation, network access); the summary says so.
"""

from __future__ import annotations

from cryptography import x509

# Android key attestation extension (KeyDescription), see
# https://source.android.com/docs/security/features/keystore/attestation
KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
SECURITY_LEVELS = {0: "Software", 1: "TEE", 2: "StrongBox"}


def split_chain(chain: bytes) -> list[bytes]:
    """u16-length-prefixed DER certificates (PROTOCOL.md §5.4). Raises ValueError."""
    certs, pos = [], 0
    while pos < len(chain):
        if len(chain) - pos < 2:
            raise ValueError("truncated length")
        length = int.from_bytes(chain[pos:pos + 2], "big")
        if pos + 2 + length > len(chain):
            raise ValueError("truncated certificate")
        certs.append(chain[pos + 2:pos + 2 + length])
        pos += 2 + length
    return certs


def _der_items(data: bytes) -> list[tuple[int, bytes]]:
    """Top-level (tag, value) pairs of a DER sequence body. Short/long lengths only."""
    items, pos = [], 0
    while pos < len(data):
        tag = data[pos]
        if tag & 0x1F == 0x1F:
            raise ValueError("multi-byte tags not expected here")
        length = data[pos + 1]
        pos += 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4:
                raise ValueError("bad DER length")
            length = int.from_bytes(data[pos:pos + n], "big")
            pos += n
        if pos + length > len(data):
            raise ValueError("DER value overruns")
        items.append((tag, data[pos:pos + length]))
        pos += length
    return items


def key_description(cert_der: bytes) -> tuple[str, bytes]:
    """(attestation security level, attestation challenge) from the leaf certificate."""
    cert = x509.load_der_x509_certificate(cert_der)
    ext = cert.extensions.get_extension_for_oid(KEY_DESCRIPTION_OID).value.value
    (tag, body), = _der_items(ext)
    if tag != 0x30:
        raise ValueError("KeyDescription is not a SEQUENCE")
    fields = _der_items(body)
    # attestationVersion, attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel, attestationChallenge
    level_tag, level = fields[1]
    challenge_tag, challenge = fields[4]
    if level_tag != 0x0A or challenge_tag != 0x04:
        raise ValueError("unexpected KeyDescription layout")
    return SECURITY_LEVELS.get(int.from_bytes(level, "big"), "unknown"), challenge


def summarize(chain: bytes | None, expected_challenge: bytes) -> str:
    if not chain:
        return "not provided"
    try:
        certs = split_chain(chain)
        level, challenge = key_description(certs[0])
    except (ValueError, IndexError, x509.ExtensionNotFound) as e:
        return f"unparsable ({e.__class__.__name__})"
    bound = "bound to this pairing" if challenge == expected_challenge else "NOT bound to this pairing"
    return f"{level}, {bound}, {len(certs)} certificates, roots not verified"
