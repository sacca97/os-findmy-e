import asyncio
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import auth_probe
from findmy import LoginState
from findmy.errors import InvalidCredentialsError


class AuthenticationTest(unittest.TestCase):
    def test_refusal_closes_account_and_saves_no_credentials_or_session(self):
        account = SimpleNamespace(
            login=AsyncMock(side_effect=InvalidCredentialsError("refused")), close=AsyncMock(),
            to_json=lambda: {"ids": {"uid": "fake", "devid": "fake"},
                "anisette": {"type": "aniLocal", "prov_data": None},
                "account": {"password": "must not persist"}, "login": {"data": "secret token"}},
        )
        with tempfile.TemporaryDirectory() as directory, \
                patch("builtins.input", return_value="fake@example.invalid"), \
                patch("getpass.getpass", return_value="fake password"):
            with self.assertRaises(InvalidCredentialsError):
                asyncio.run(auth_probe.authenticate(account, Path(directory)))
            saved = json.loads((Path(directory) / "identity.json").read_text())
            self.assertEqual(set(saved), {"ids", "anisette"})
            self.assertEqual((Path(directory) / "identity.json").stat().st_mode & 0o777, 0o600)
        account.login.assert_awaited_once()
        account.close.assert_awaited_once()

    def test_trace_prints_request_shape_without_secret_values(self):
        account = SimpleNamespace(_ENDPOINT_GSA="fake-url", _http=SimpleNamespace(post=AsyncMock()),
                                  _gsa_request=AsyncMock(return_value={"Status": {"ec": -80045}}))
        auth_probe.trace_requests(account)
        output = io.StringIO()
        with redirect_stdout(output):
            asyncio.run(account._http.post("fake-url", headers={}, data=auth_probe.plistlib.dumps({
                "Request": {"u": "private email", "A2k": b"secret exchange", "cpd": {
                    "X-Apple-I-MD": "private OTP", "X-Apple-I-MD-M": "private machine"}}})))
            asyncio.run(account._gsa_request({"o": "init"}))
        for secret in ("private email", "secret exchange", "private OTP", "private machine"):
            self.assertNotIn(secret, output.getvalue())
        self.assertIn("-80045", output.getvalue())


class LoggedInPathTest(unittest.TestCase):
    """The branch that only runs after a successful login: probe, save-session and --watch.

    A real run costs a login and an SMS code, so this exercises that branch with fakes. It once
    failed because `authenticate` reused the name `state` for both the login result and the
    machine's state directory.
    """

    def test_watch_and_save_session_after_login(self):
        statuses = []

        async def post(url, auth=None, headers=None, json=None):
            statuses.append(auth[1])
            return SimpleNamespace(status_code=401 if auth[1].endswith(("A", "B")) else 200, content=b"x", headers={})

        def fake_account():
            return SimpleNamespace(
                dsid="123", close=AsyncMock(), get_anisette_headers=AsyncMock(return_value={}),
                _http=SimpleNamespace(post=post),
                _login_state_data={"mobileme_data": {"tokens": {"searchPartyToken": "tok123"}}},
                login=AsyncMock(return_value=LoginState.LOGGED_IN),
                to_json=lambda: (_ for _ in ()).throw(NotImplementedError()))

        with tempfile.TemporaryDirectory() as directory:
            machine = Path(directory) / "machine"
            (machine / "store").mkdir(parents=True)
            (machine / "store" / "adi.pb").write_bytes(b"x")
            session = Path(directory) / "session.json"
            output = io.StringIO()
            with patch("builtins.input", return_value="fake@example.invalid"), \
                    patch("getpass.getpass", return_value="fake password"), \
                    patch.object(auth_probe, "make_mac_account", return_value=fake_account()), \
                    redirect_stdout(output):
                code = asyncio.run(auth_probe.authenticate(
                    fake_account(), Path(directory) / "state", None, None, str(session), False,
                    1, machine, 1))
            self.assertEqual(code, 0)
            self.assertIn("[watch]", output.getvalue())
            self.assertIn("bad 401", output.getvalue())
            self.assertEqual(json.loads(session.read_text())["searchPartyToken"], "tok123")
            self.assertEqual(session.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
