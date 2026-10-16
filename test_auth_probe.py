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


if __name__ == "__main__":
    unittest.main()
