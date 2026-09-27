"""Malformed input never crashes the decoder or the verifier (SECURITY.md T-10).

Deterministic seed so failures are reproducible.
"""

import random
import unittest

from phonekey import codec
from phonekey.codec import ProtocolError
from tests.helpers import VerifierTestCase

ITERATIONS = 3000


def mutations(rng: random.Random, data: bytes):
    """Yields bit flips, truncations, extensions, splices and random garbage."""
    for _ in range(ITERATIONS):
        choice = rng.randrange(6)
        b = bytearray(data)
        if choice == 0 and b:
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif choice == 1:
            b = b[:rng.randrange(len(b) + 1)]
        elif choice == 2:
            b += rng.randbytes(rng.randrange(1, 64))
        elif choice == 3 and len(b) > 4:
            i = rng.randrange(4, len(b))
            b[i:i] = rng.randbytes(rng.randrange(1, 8))
        elif choice == 4 and len(b) > 7:
            i = rng.randrange(4, len(b) - 2)
            b[i + 1:i + 3] = rng.randrange(0x10000).to_bytes(2, "big")  # corrupt a length
        else:
            b = bytearray(b"PK\x01" + rng.randbytes(rng.randrange(0, 200)))
        yield bytes(b)


class CodecFuzzTest(VerifierTestCase):
    def test_decoder_only_raises_protocol_error(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        rng = random.Random(0x50484B)
        for seed in (request, response):
            for data in mutations(rng, seed):
                try:
                    codec.decode(data)
                except ProtocolError:
                    pass

    def test_verifier_never_raises_or_accepts_mutated_responses(self):
        rng = random.Random(0xBEEF)
        for _ in range(40):
            request_id, request = self.request()
            response = self.phone.handle_auth_request(request)
            for data in mutations(random.Random(rng.random()), response):
                if data == response:
                    continue
                result = self.verifier.complete_auth(data)
                self.assertFalse(result.ok, data.hex())
                if request_id not in self.verifier._pending:
                    break  # a mutation consumed the request; start a new one
            self.verifier.cancel(request_id)

    def test_phone_side_never_raises_on_mutated_requests(self):
        _, request = self.request()
        for data in mutations(random.Random(7), request):
            reply = self.phone.handle_auth_request(data)
            if data != request:
                self.assertEqual(codec.MsgType.ERROR, codec.decode(reply).type)


if __name__ == "__main__":
    unittest.main()
