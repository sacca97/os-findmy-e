"""Offline tests for the resync tooling: nothing here touches the network or Apple."""
import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools" / "machoadi"))

import auth_probe  # noqa: E402
import cooldown  # noqa: E402
import mac_anisette  # noqa: E402
import resync  # noqa: E402


class CooldownTest(unittest.TestCase):
    def test_guard_refuses_inside_the_cooldown_and_passes_after_it(self):
        with tempfile.TemporaryDirectory() as d, patch.object(cooldown, "MARKER", Path(d) / "m"):
            cooldown.guard()  # no marker: passes
            cooldown.note_429(time.time() - 60)
            with self.assertRaises(SystemExit) as ctx:
                cooldown.guard()
            self.assertIn("Nothing was sent", str(ctx.exception))
            cooldown.guard(ignore=True)
            cooldown.note_429(time.time() - (cooldown.COOLDOWN_MINUTES + 1) * 60)
            cooldown.guard()

    def test_429_detection(self):
        self.assertTrue(cooldown.looks_like_429("The Grand Slam request was refused with HTTP 429."))
        self.assertFalse(cooldown.looks_like_429("refused with HTTP 401"))


class ProvisionedAtTest(unittest.TestCase):
    def test_identity_wins_over_store_mtime(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            (state / "store").mkdir()
            (state / "store" / "adi-1.pb").write_bytes(b"x")  # fresh mtime: the last OTP
            (state / "identity.json").write_text(json.dumps({"provisioned_at": 1000.0}))
            self.assertEqual(mac_anisette.provisioned_at(state), 1000.0)

    def test_legacy_adi_pb_is_the_fallback_for_old_states(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            (state / "store").mkdir()
            (state / "identity.json").write_text("{}")
            legacy = state / "store" / "adi.pb"
            legacy.write_bytes(b"x")
            import os
            os.utime(legacy, (500, 500))
            (state / "store" / "adi-1.pb").write_bytes(b"y")
            self.assertEqual(mac_anisette.provisioned_at(state), 500)


def make_resyncer(probes, sync_ok=True):
    """A Resyncer with the network and CoreADI replaced by scripted answers."""
    r = resync.Resyncer.__new__(resync.Resyncer)
    r.born, r.requests, r.max_requests, r.last_sync, r.on_synced = time.time() - 100, 0, 40, None, None
    r._log = lambda row: r.rows.append(row)
    r.rows = []
    answers = iter(probes)

    async def probe():
        return next(answers)

    r.probe = probe
    r.synchronize = lambda sim: {"ret": 0, "mid": b"m", "srm": b"s"}
    r.sync_machine = lambda mid, srm: {"ec": 0 if sync_ok else -1, "hsc": 200}
    return r


class EnsureFreshTest(unittest.TestCase):
    def run_it(self, r):
        return asyncio.run(r.ensure_fresh())

    def test_accepted_machine_is_left_alone(self):
        r = make_resyncer([{"ec": -20970, "hsc": 200, "sim_b64": None}])
        self.assertEqual(self.run_it(r), "accepted")

    def test_434_with_sim_is_synchronised_and_revived(self):
        r = make_resyncer([{"ec": -22421, "hsc": 434, "sim_b64": "QQ=="}, {"ec": -20970, "hsc": 200}])
        self.assertEqual(self.run_it(r), "revived")
        self.assertIsNotNone(r.last_sync)

    def test_434_that_stays_refused_after_sync(self):
        r = make_resyncer([{"ec": -22421, "hsc": 434, "sim_b64": "QQ=="}, {"ec": -22421, "hsc": 434}])
        self.assertEqual(self.run_it(r), "refused")

    def test_434_without_sim_cannot_be_answered(self):
        r = make_resyncer([{"ec": -22421, "hsc": 434, "sim_b64": None}])
        self.assertEqual(self.run_it(r), "refused")

    def test_sync_rejected_is_reported_not_retried(self):
        r = make_resyncer([{"ec": -22421, "hsc": 434, "sim_b64": "QQ=="}], sync_ok=False)
        self.assertEqual(self.run_it(r), "refused")

    def test_transport_error_is_unknown(self):
        r = make_resyncer([{"error": "ConnectError: x", "sim_b64": None}])
        self.assertEqual(self.run_it(r), "unknown")

    def test_request_cap_stops_the_run(self):
        r = make_resyncer([])
        r.requests, r.max_requests = 40, 40
        with patch.object(cooldown, "guard"), self.assertRaises(SystemExit):
            r._spend()


class AutoResyncHookTest(unittest.TestCase):
    def test_434_is_answered_and_the_request_repeated_once(self):
        replies = [{"Status": {"hsc": 434, "ec": -22421, "X-Apple-I-MD-DATA": "QQ=="}},
                   {"Status": {"hsc": 200, "ec": 0}}]
        calls = []

        async def inner(parameters):
            calls.append(parameters["o"])
            return replies[len(calls) - 1]

        account = SimpleNamespace(_gsa_request=inner, _anisette=SimpleNamespace(_window=7))
        answered = []

        async def answer_sim(sim):
            answered.append(sim)
            return {"ok": True}

        resyncer = SimpleNamespace(age=lambda: 99, answer_sim=answer_sim, on_synced=None)
        auth_probe.install_auto_resync(account, resyncer)
        response = asyncio.run(account._gsa_request({"o": "complete"}))
        self.assertEqual(calls, ["complete", "complete"])
        self.assertEqual(answered, ["QQ=="])
        self.assertEqual(response["Status"]["ec"], 0)
        resyncer.on_synced()
        self.assertIsNone(account._anisette._window)

    def test_other_answers_pass_through_untouched(self):
        async def inner(parameters):
            return {"Status": {"hsc": 409, "ec": 0}}

        account = SimpleNamespace(_gsa_request=inner, _anisette=SimpleNamespace(_window=7))
        resyncer = SimpleNamespace(age=lambda: 1, answer_sim=None, on_synced=None)
        auth_probe.install_auto_resync(account, resyncer)
        self.assertEqual(asyncio.run(account._gsa_request({"o": "init"}))["Status"]["hsc"], 409)


class FetchReportsTest(unittest.TestCase):
    def test_body_is_identical_to_the_librarys_own(self):
        import fetch_reports
        from datetime import datetime, timezone
        from findmy import AsyncAppleAccount

        sent = {}

        class Http:
            async def post(self, url, **kw):
                sent.update(url=url, json=kw["json"])
                return SimpleNamespace(status_code=200, ok=True, text=lambda: "{}",
                                       json=lambda: {"acsnLocations": {"statusCode": "200"}})

        async def headers():
            return {}

        fake = SimpleNamespace(dsid="1", service_tokens={"searchPartyToken": "t"}, _http=Http(),
                               get_anisette_headers=headers, _ENDPOINT_REPORTS_FETCH=fetch_reports.URL)
        raw = getattr(AsyncAppleAccount.fetch_raw_reports, "__wrapped__", AsyncAppleAccount.fetch_raw_reports)
        asyncio.run(raw(fake, [(["HASH"], [])]))
        mine = fetch_reports.build_body("HASH", 7, now=datetime.now(tz=timezone.utc))
        self.assertEqual(sent["url"], fetch_reports.URL)
        for body in (sent["json"], mine):
            for entry in body["fetch"]:  # timestamps differ by at most the second between the two calls
                for k in ("startDate", "startDateSecondary", "endDate"):
                    entry[k] //= 10_000
        self.assertEqual(sent["json"], mine)

    def test_parse_payload(self):
        import base64
        import fetch_reports
        answer = {"acsnLocations": {"statusCode": "200", "locationPayload": [
            {"id": base64.b64encode(b"k").decode(), "locationInfo": [base64.b64encode(b"r1").decode()]}]}}
        self.assertEqual(fetch_reports.parse_payload(answer), ("200", [(b"k", b"r1")]))
        self.assertEqual(fetch_reports.parse_payload({}), (None, []))


class CloudKitIdentityTest(unittest.TestCase):
    def test_a_provisioning_udid_is_replaced_by_the_host_uuid_for_cloudkit_only(self):
        import uuid as uuid_module
        import tag_keys

        real = SimpleNamespace(device_uuid="00006000-0123456789ABCDEF", dsid="1",
                               _anisette=SimpleNamespace(identity_json={"host_uuid": "ab" * 16}))
        with self.assertRaises(ValueError):  # what the library did with the real value
            uuid_module.UUID(real.device_uuid)
        wrapped = tag_keys.for_cloudkit(real)
        self.assertEqual(uuid_module.UUID(wrapped.device_uuid).hex, "ab" * 16)
        self.assertEqual(wrapped.dsid, "1")                                   # forwarded
        self.assertEqual(real.device_uuid, "00006000-0123456789ABCDEF")       # the real account is untouched

    def test_a_valid_uuid_is_left_alone(self):
        import tag_keys
        real = SimpleNamespace(device_uuid="12345678-1234-5678-1234-567812345678")
        self.assertIs(tag_keys.for_cloudkit(real), real)


class ReadAccessoriesTest(unittest.TestCase):
    def test_reports_counts_and_says_which_beacons_are_devices(self):
        import tag_keys
        from unittest.mock import AsyncMock, MagicMock

        tag = SimpleNamespace(record_type="MasterBeaconRecord", name="t", values={
            "model": "", "privateKey": b"k", "sharedSecret2": b"s"})
        phone = SimpleNamespace(record_type="MasterBeaconRecord", name="p", values={
            "model": "iPhone15,2", "secureLocationsSharedSecret": b"s"})
        decrypted = type("D", (list,), {})([tag, phone])
        decrypted.skipped = {"no key held": 1}
        store = MagicMock()
        store.zone_keys = AsyncMock(return_value=["zk"])
        store.fetch_records = AsyncMock(return_value=[tag, phone, SimpleNamespace(record_type="Other", name="x")])
        store.zone_record_defaults = AsyncMock(return_value=[])
        said = []
        with patch("findmy.cloudkit.beacons.decrypt_records", return_value=decrypted), \
                patch("findmy.cloudkit.beacons.group_records",
                      return_value=[SimpleNamespace(beacon=tag, naming=None), SimpleNamespace(beacon=phone, naming=None)]), \
                patch("findmy.cloudkit.beacons.accessories_from_records", return_value=["acc"]):
            result = asyncio.run(tag_keys.read_accessories(store, ["k"], said.append))
        text = "\n".join(said)
        self.assertEqual(result, ["acc"])
        self.assertIn("fetched 3 BeaconStore record(s)", text)
        self.assertIn("1 x Other", text)
        self.assertIn("no key held", text)
        self.assertIn("private key=yes", text)
        self.assertIn("private key=NO", text)
        self.assertNotIn("b'k'", text)


class SavedTagsTest(unittest.TestCase):
    def test_saved_accessories_load_and_are_fetched_without_any_keychain(self):
        import tag_keys
        from unittest.mock import AsyncMock
        from findmy import FindMyAccessory

        item = {"type": "accessory", "master_key": "00" * 28, "skn": "11" * 32, "sks": "22" * 32,
                "paired_at": "2026-10-14T11:24:03+00:00", "name": "Test", "model": "Smart Tracker",
                "identifier": "00000000-0000-4000-8000-000000000001", "group_identifier": None,
                "serial_number": None, "alignment_date": "2026-10-14T11:24:03+00:00", "alignment_index": 1}
        FindMyAccessory.from_json(item)  # the saved shape must load
        path = Path(tempfile.mkdtemp()) / "tags.json"
        path.write_text(json.dumps([item]))
        account = SimpleNamespace(fetch_location_history=AsyncMock(return_value=[]))
        said = []
        code = asyncio.run(tag_keys.fetch_saved(account, str(path), said.append))
        self.assertEqual(code, 0)
        account.fetch_location_history.assert_awaited_once()
        self.assertIn("Test: 0 report(s)", "\n".join(said))
        self.assertEqual(asyncio.run(tag_keys.fetch_saved(account, "/nonexistent", said.append)), 1)


class TagKeysTest(unittest.TestCase):
    """The passcode guard rails, with the keychain and CloudKit replaced by fakes."""

    def run_flow(self, answers, *, list_only=False, recover_fails=False, several=False):
        import tag_keys
        from unittest.mock import AsyncMock, MagicMock

        record = SimpleNamespace(describe=lambda: "iPhone 15 (record)", device_name="iPhone")
        session = MagicMock()
        session.recovery_options = AsyncMock(return_value=SimpleNamespace(
            recoverable=[record, record] if several else [record], described_but_not_viable=[]))
        session.recover = AsyncMock(side_effect=RuntimeError("wrong passcode") if recover_fails else None)
        session.pcs_keys = AsyncMock(return_value=[object()])
        session.close = AsyncMock()
        store = MagicMock()
        store.close = AsyncMock()
        asked, said = [], []
        replies = iter(answers)

        def ask(prompt):
            asked.append(prompt)
            return next(replies)

        secret_calls = []

        def ask_secret(prompt):
            secret_calls.append(prompt)
            return "123456"

        with patch("findmy.keychain.session.AsyncKeychainSession.open", AsyncMock(return_value=session)), \
                patch("findmy.cloudkit.AsyncBeaconStore", return_value=store), \
                patch.object(tag_keys, "read_accessories", AsyncMock(return_value=[])):
            try:
                code = asyncio.run(tag_keys.run(SimpleNamespace(device_uuid="12345678-1234-5678-1234-567812345678"), list_only=list_only, ask=ask,
                                                ask_secret=ask_secret, say=said.append))
            except RuntimeError as error:
                code = f"raised {error}"
        return code, session, secret_calls, said

    def test_list_only_never_asks_for_a_passcode_or_recovers(self):
        code, session, secrets_asked, _ = self.run_flow([], list_only=True)
        self.assertEqual(code, 0)
        self.assertEqual(secrets_asked, [])
        session.recover.assert_not_called()

    def test_single_record_is_chosen_without_a_question_and_asks_only_for_the_passcode(self):
        code, session, secrets_asked, _ = self.run_flow([])
        self.assertEqual(code, 0)
        self.assertEqual(len(secrets_asked), 1)
        session.recover.assert_awaited_once()

    def test_bad_record_number_sends_nothing_when_there_are_several(self):
        code, session, secrets_asked, _ = self.run_flow(["7"], several=True)
        self.assertEqual(code, 1)
        self.assertEqual(secrets_asked, [])
        session.recover.assert_not_called()

    def test_wrong_passcode_is_tried_exactly_once_and_not_retried(self):
        code, session, secrets_asked, _ = self.run_flow([], recover_fails=True)
        self.assertEqual(len(secrets_asked), 1)
        self.assertEqual(session.recover.await_count, 1)
        self.assertIn("raised", str(code))
        session.close.assert_awaited()

    def test_flow_never_joins(self):
        code, session, secrets_asked, said = self.run_flow([])
        self.assertEqual(code, 0)
        session.recover.assert_awaited_once()
        session.join.assert_not_called()
        self.assertFalse(any("123456" in line for line in said))


class LoginStoreTest(unittest.TestCase):
    def test_roundtrip_mode_and_machine_binding(self):
        import login_store
        from findmy import LoginState

        state = Path(tempfile.mkdtemp())
        ident = {"device_id": "00006000-AAAAAAAAAAAAAAAA", "local_user_uuid": "U" * 32, "serial": "S" * 12,
                 "client_info": "<MacBookPro13,2> <macOS;13.1;22C65>", "host_uuid": "h"}
        (state / "identity.json").write_text(json.dumps(ident))
        account = SimpleNamespace(
            _uid="U" * 32, _devid=ident["device_id"], _username="me@example.invalid", _password="pw",
            _account_info={"a": 1}, _device_name=None, _login_state=LoginState.LOGGED_IN,
            _login_state_data={"mobileme_data": {"tokens": {"searchPartyToken": "tok"}}})
        path = state / "login.json"
        login_store.save(account, path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        restored = login_store.restore(state, path)
        self.assertEqual(restored._username, "me@example.invalid")
        self.assertEqual(restored._password, "pw")
        self.assertEqual(restored._login_state, LoginState.LOGGED_IN)
        self.assertEqual(restored._login_state_data["mobileme_data"]["tokens"]["searchPartyToken"], "tok")
        asyncio.run(restored.close())
        # without the password
        login_store.save(account, path, keep_password=False)
        self.assertNotIn("pw", path.read_text())
        # a different machine is refused
        (state / "identity.json").write_text(json.dumps({**ident, "device_id": "00006000-BBBBBBBBBBBBBBBB"}))
        with self.assertRaises(SystemExit):
            login_store.restore(state, path)


if __name__ == "__main__":
    unittest.main()
