"""Attestation summary (informational only, SECURITY.md D-5) on synthetic certificates."""

import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from phonekey import attestation


def der(tag: int, value: bytes) -> bytes:
    assert len(value) < 0x80 or len(value) < 0x10000
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    return bytes([tag, 0x82]) + len(value).to_bytes(2, "big") + value


def key_description(level: int, challenge: bytes) -> bytes:
    body = (der(0x02, b"\x64") + der(0x0A, bytes([level])) + der(0x02, b"\x64") + der(0x0A, bytes([level]))
            + der(0x04, challenge) + der(0x04, b"") + der(0x30, b"") + der(0x30, b""))
    return der(0x30, body)


def cert(extension: bytes | None) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Android Keystore Key")])
    now = datetime.datetime(2026, 1, 1)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    if extension is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(attestation.KEY_DESCRIPTION_OID, extension), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def chain(*certs: bytes) -> bytes:
    return b"".join(len(c).to_bytes(2, "big") + c for c in certs)


class AttestationTest(unittest.TestCase):
    CHALLENGE = bytes(range(32))

    def test_tee_bound_to_pairing(self):
        summary = attestation.summarize(chain(cert(key_description(1, self.CHALLENGE)), cert(None)), self.CHALLENGE)
        self.assertEqual("TEE, bound to this pairing, 2 certificates, roots not verified", summary)

    def test_strongbox_level(self):
        summary = attestation.summarize(chain(cert(key_description(2, self.CHALLENGE))), self.CHALLENGE)
        self.assertTrue(summary.startswith("StrongBox, bound"))

    def test_challenge_mismatch_is_reported(self):
        summary = attestation.summarize(chain(cert(key_description(1, bytes(32)))), self.CHALLENGE)
        self.assertIn("NOT bound to this pairing", summary)

    def test_missing_extension_and_garbage(self):
        self.assertEqual("unparsable (ExtensionNotFound)",
                         attestation.summarize(chain(cert(None)), self.CHALLENGE))
        self.assertEqual("unparsable (ValueError)", attestation.summarize(b"\x00\x05ab", self.CHALLENGE))
        self.assertEqual("not provided", attestation.summarize(None, self.CHALLENGE))


if __name__ == "__main__":
    unittest.main()
