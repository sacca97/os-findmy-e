"""Offline checks against the Apple executable and optional local fixtures."""

import base64
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from macos_adi_emulator.adi import Adid, AdidError


@unittest.skipUnless(os.environ.get("MACOS_ADI_BINARY"), "set MACOS_ADI_BINARY")
class AdidTests(unittest.TestCase):
    def setUp(self):
        self.d = Adid(host_uuid=bytes(range(16)))

    def assert_status(self, code, method, *args):
        with self.assertRaises(AdidError) as error:
            method(*args)
        self.assertEqual(error.exception.code, code)

    def restored(self):
        path = os.environ.get("MACOS_ADI_TEST_STATE")
        if not path:
            self.skipTest("set MACOS_ADI_TEST_STATE to a saved Anisette JSON file")
        state = json.loads(base64.b64decode(json.loads(Path(path).read_text())["adi_pb"]))
        d = Adid(host_uuid=bytes.fromhex(state["host_uuid"]))
        for path, value in state["files"].items():
            d.stubs.files[path] = bytearray(base64.b64decode(value))
        return d

    def spim(self):
        path = os.environ.get("MACOS_ADI_TEST_EXCHANGE")
        if not path:
            self.skipTest("set MACOS_ADI_TEST_EXCHANGE to a recorded exchange JSON file")
        return base64.b64decode(json.loads(Path(path).read_text())["spim"])

    def test_unprovisioned_errors_and_recovery(self):
        d = self.d
        self.assertFalse(d.is_machine_provisioned(-2))
        self.assertEqual(d.get_all_provisioned_accounts(), [])
        self.assert_status(-45061, d.request_otp, -2)
        self.assert_status(-45061, d.get_idms_routing, -2)
        self.assert_status(-45062, d.erase, -2)
        self.assert_status(-45026, d.destroy_provisioning_session, 0)
        self.assert_status(-45025, d.destroy_provisioning_session, 0xFFFFFFFF)
        self.assert_status(-45032, d.start_provisioning, -2, b"")
        self.assertFalse(d.is_machine_provisioned(-2))

    def test_provisioning_session_survives_other_requests_and_errors(self):
        spim = self.spim()
        cpim, session = self.d.start_provisioning(-2, spim)
        self.assertEqual(len(cpim), 276)
        self.assertEqual(cpim[:4], b"\0\0\0\5")
        self.assertNotEqual(session, 0)
        self.assertFalse(self.d.is_machine_provisioned(-2))
        self.assert_status(-45063, self.d.start_provisioning, -2, spim)
        self.d.destroy_provisioning_session(session)
        _, session = self.d.start_provisioning(-2, spim)
        self.d.destroy_provisioning_session(session)

    def test_cpim_reproducibility_with_fixed_entropy_and_clock(self):
        spim = self.spim()

        def cpim_at(timestamp):
            with (
                patch("macos_adi_emulator.adi.time.time", return_value=timestamp),
                patch("macos_adi_emulator.stubs.secrets.randbits", return_value=42),
                patch("macos_adi_emulator.stubs.secrets.token_bytes", side_effect=lambda n: b"*" * n),
            ):
                d = Adid(host_uuid=bytes(range(16)))
                return d.start_provisioning(-2, spim)[0]

        cpim = cpim_at(1700000000)
        self.assertEqual(cpim, cpim_at(1700000000.5))
        self.assertNotEqual(cpim, cpim_at(1700000001))

    def test_repeated_otp_keeps_request_memory_bounded(self):
        d = self.restored()
        h = d.harness

        def footprint():
            return (h._scratch_cur, h._obj_cur, len(d._objects),
                    d.stubs._next_url, len(d.stubs.urls), len(d.stubs.fds),
                    len(h._heap_allocations))

        initial = footprint()
        mid = None
        for _ in range(100):
            self.assertTrue(d.is_machine_provisioned(-2))
            machine, otp = d.request_otp(-2)
            self.assertEqual((len(machine), len(otp)), (60, 28))
            if mid is not None:
                self.assertEqual(machine, mid)
            mid = machine
            self.assertEqual(footprint(), initial)

    def test_routing_restore_erase_and_instance_isolation(self):
        d = self.restored()
        self.assertFalse(d.is_machine_provisioned(123456))
        mid, _ = d.request_otp(-2)
        accounts = d.get_all_provisioned_accounts()
        self.assertEqual([a["ds_id"] for a in accounts], [-2])
        self.assertEqual(accounts[0]["mid"], mid)
        for routing in (0, 1, (1 << 64) - 1):
            d.set_idms_routing(-2, routing)
            self.assertEqual(d.get_idms_routing(-2), routing)
        clone = Adid(host_uuid=d.stubs.hostuuid)
        clone.stubs.files = {p: bytearray(v) for p, v in d.stubs.files.items()}
        self.assertTrue(clone.is_machine_provisioned(-2))
        self.assertEqual(clone.get_idms_routing(-2), routing)
        with patch("macos_adi_emulator.adi.time.time", return_value=1700000000):
            self.assertEqual(clone.request_otp(-2), d.request_otp(-2))
        clone.erase(-2)
        self.assertFalse(clone.is_machine_provisioned(-2))
        self.assert_status(-45061, clone.request_otp, -2)
        self.assertTrue(d.is_machine_provisioned(-2))
