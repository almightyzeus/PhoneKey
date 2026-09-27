"""ATT client against a scripted PhoneKey GATT server."""

import struct
import unittest

from phonekey import att
from phonekey.att import AttClient, uuid128_le

SERVICE = "eb109ed5-92be-4d34-a98d-61bb7f350b41"
A2V = "f3c11509-8693-4342-ae5b-8d0f7e6e50fa"
V2A = "955060b9-442a-41f4-bea8-251ea1f42f85"
OTHER = "00002a00-0000-1000-8000-00805f9b34fb"


class FakeServer:
    """Answers the client's requests like Android's GATT server with the PhoneKey service at 0x0028."""

    SVC_START, SVC_END = 0x0028, 0x002E
    # decl, value handle, uuid: A2V (indicate) at 0x2A, its CCCD at 0x2B, V2A at 0x2D
    CHARS = [(0x0029, 0x002A, A2V), (0x002C, 0x002D, V2A)]
    CCCD = 0x002B

    def __init__(self, mtu=517, refuse_cccd=False, service_present=True):
        self.mtu, self.refuse_cccd, self.service_present = mtu, refuse_cccd, service_present
        self.cccd = b"\x00\x00"
        self.writes = []
        self.to_client = []

    def handle(self, pdu: bytes) -> None:
        op = pdu[0]
        if op == att.MTU_REQ:
            self.to_client.append(bytes([att.MTU_RSP]) + struct.pack("<H", self.mtu))
        elif op == att.FIND_BY_TYPE_REQ:
            if self.service_present and pdu[7:] == uuid128_le(SERVICE):
                self.to_client.append(bytes([att.FIND_BY_TYPE_RSP]) + struct.pack("<HH", self.SVC_START, self.SVC_END))
            else:
                self.to_client.append(bytes([att.ERROR_RSP, op, 1, 0, att.ERR_ATTRIBUTE_NOT_FOUND]))
        elif op == att.READ_BY_TYPE_REQ:
            start, end = struct.unpack_from("<HH", pdu, 1)
            chars = [c for c in self.CHARS if start <= c[0] <= end][:1]  # one per response, like a small MTU
            if not chars:
                self.to_client.append(bytes([att.ERROR_RSP, op, 0, 0, att.ERR_ATTRIBUTE_NOT_FOUND]))
            else:
                decl, value, uuid = chars[0]
                entry = struct.pack("<HBH", decl, 0x20 if uuid == A2V else 0x08, value) + uuid128_le(uuid)
                self.to_client.append(bytes([att.READ_BY_TYPE_RSP, len(entry)]) + entry)
        elif op == att.FIND_INFO_REQ:
            start, end = struct.unpack_from("<HH", pdu, 1)
            if start <= self.CCCD <= end:
                self.to_client.append(bytes([att.FIND_INFO_RSP, 1]) + struct.pack("<HH", self.CCCD, att.CCCD))
            else:
                self.to_client.append(bytes([att.ERROR_RSP, op, 0, 0, att.ERR_ATTRIBUTE_NOT_FOUND]))
        elif op == att.WRITE_REQ:
            handle = struct.unpack_from("<H", pdu, 1)[0]
            if handle == self.CCCD and self.refuse_cccd:
                self.to_client.append(bytes([att.ERROR_RSP, op, 0, 0, 0x05]))  # insufficient authentication
                return
            if handle == self.CCCD:
                self.cccd = pdu[3:]
            else:
                self.writes.append((handle, pdu[3:]))
            self.to_client.append(bytes([att.WRITE_RSP]))


class AttClientTest(unittest.TestCase):
    def setUp(self):
        self.sent, self.values, self.errors, self.ready = [], [], [], []

    def make(self, server: FakeServer) -> AttClient:
        self.server = server
        self.client = AttClient(SERVICE, A2V, V2A, self.sent.append, self.ready.append,
                                self.values.append, self.errors.append)
        return self.client

    def run_exchange(self):
        """Delivers requests to the server and responses back until quiet."""
        while self.sent or self.server.to_client:
            while self.sent:
                pdu = self.sent.pop(0)
                if pdu[0] in (att.CONFIRM,) or pdu[0] == att.ERROR_RSP or pdu[0] == att.MTU_RSP:
                    self.server_replies = getattr(self, "server_replies", []) + [pdu]
                    continue
                self.server.handle(pdu)
            while self.server.to_client:
                self.client.feed(self.server.to_client.pop(0))

    def test_setup_finds_handles_and_subscribes(self):
        client = self.make(FakeServer(mtu=247))
        client.start()
        self.run_exchange()
        self.assertEqual([247], self.ready)
        self.assertEqual((0x2A, 0x2D, 0x2B), (client.notify_handle, client.write_handle, client.cccd_handle))
        self.assertEqual(att.CCCD_INDICATE, self.server.cccd)
        self.assertEqual([], self.errors)

    def test_mtu_is_clamped(self):
        client = self.make(FakeServer(mtu=10))
        client.start()
        self.run_exchange()
        self.assertEqual(att.DEFAULT_MTU, client.mtu)

    def test_writes_are_serialized(self):
        client = self.make(FakeServer())
        client.start()
        self.run_exchange()
        client.write(b"one")
        client.write(b"two")
        self.assertEqual(1, len(self.sent))  # second waits for the first response
        self.run_exchange()
        self.assertEqual([(0x2D, b"one"), (0x2D, b"two")], self.server.writes)

    def test_indications_are_delivered_and_confirmed(self):
        client = self.make(FakeServer())
        client.start()
        self.run_exchange()
        client.feed(bytes([att.INDICATE]) + struct.pack("<H", 0x2A) + b"frame")
        self.assertEqual([b"frame"], self.values)
        self.assertEqual(bytes([att.CONFIRM]), self.sent[-1])

    def test_indications_on_other_handles_are_confirmed_but_ignored(self):
        client = self.make(FakeServer())
        client.start()
        self.run_exchange()
        client.feed(bytes([att.INDICATE]) + struct.pack("<H", 0x05) + b"service changed")
        self.assertEqual([], self.values)
        self.assertEqual(bytes([att.CONFIRM]), self.sent[-1])

    def test_missing_service_fails(self):
        client = self.make(FakeServer(service_present=False))
        client.start()
        self.run_exchange()
        self.assertEqual(["PhoneKey service not found on the phone"], self.errors)
        self.assertEqual([], self.ready)

    def test_refused_subscription_fails(self):
        client = self.make(FakeServer(refuse_cccd=True))
        client.start()
        self.run_exchange()
        self.assertTrue(self.errors and "0x05" in self.errors[0])

    def test_requests_from_phone_get_answers(self):
        client = self.make(FakeServer())
        client.feed(bytes([att.MTU_REQ]) + struct.pack("<H", 512))
        self.assertEqual(att.MTU_RSP, self.sent[-1][0])
        client.feed(bytes([0x10]) + struct.pack("<HHH", 1, 0xFFFF, 0x2800))  # Read By Group Type
        self.assertEqual(bytes([att.ERROR_RSP, 0x10, 0, 0, att.ERR_ATTRIBUTE_NOT_FOUND]), self.sent[-1])
        client.feed(bytes([0x0A, 3, 0]))  # Read Request
        self.assertEqual(att.ERR_REQUEST_NOT_SUPPORTED, self.sent[-1][4])

    def test_unsolicited_and_truncated_input_is_harmless(self):
        client = self.make(FakeServer())
        client.feed(bytes([att.WRITE_RSP]))  # nothing pending
        client.feed(b"")
        client.start()
        client.feed(bytes([att.MTU_RSP]))  # truncated response
        self.assertTrue(self.errors)

    def test_write_before_ready_is_refused(self):
        client = self.make(FakeServer())
        with self.assertRaises(att.AttError):
            client.write(b"x")


if __name__ == "__main__":
    unittest.main()
