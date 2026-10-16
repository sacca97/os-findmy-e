"""Does the developer-services flow that sideloading tools need accept this machine? Read-only.

Sideloading tools (AltStore, SideStore, iloader, xtool, isideload) do two things after the login that this project
never tried:

  1. ask Grand Slam for an Xcode **app token** (`o: apptokens`, app `com.apple.gs.xcode.auth`);
  2. call the developer-services API with it (`listTeams`; nothing is created or changed).

Step 1 is where `-22411` appears in SideStore#1658 and isideload#27: the login (`init`, the password proof) passes and the
app-token request is refused. isideload#27 fixed it by using the device values the real client pairs with its Anisette.
This project's device values are made up, so this check can hit exactly that refusal. Either answer is informative.

Runs INSIDE a fresh login (`auth_probe.py --dev-check`): the app-token request is signed with `sk` and carries `c` and
the idms token, all inside the decrypted `spd` blob of the final `complete`. The library throws that blob away after
login and the saved login does not keep it (it is more sensitive than the tokens), so a restored login cannot do this.

The request, the decryption and the `listTeams` call were checked against AltSign (rileytestut/AltSign,
`ALTAppleAPI+Authentication.m` and `ALTAppleAPI.m`) and SideStore/apple-private-apis `get_app_token`:

    {"o": "apptokens", "app": [APP], "c": <spd c>, "t": <spd GsIdmsToken>, "u": <spd adsid>,
     "checksum": HMAC-SHA256(<spd sk>, "apptokens" + adsid + APP), "cpd": <anisette>}

The verdict is Apple's `Status` (`ec 0`, or the refusal code). The token comes back encrypted in `et`; it is decrypted
as AltSign's `ALTDecryptDataGCM` does it: AES-GCM, key `sk`, layout `"XYZ" + iv(16) + ciphertext + tag(16)`, `"XYZ"` as
associated data, plist `t -> app -> {token, expiry}`. If decryption fails anyway, the check says so and stops after step 1
with the verdict already known.
Nothing secret is printed: no `sk`, `c`, token or Apple ID, only status codes, key *names* and counts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import plistlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

APP = "com.apple.gs.xcode.auth"
DEV_URL = "https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=XABBG36SBA"

_captured: dict = {}


def install_spd_capture() -> None:
    """Remember the decrypted `spd` of every `complete`; the last one belongs to the final session."""
    from findmy.util import crypto, parsers  # noqa: PLC0415

    original = crypto.decrypt_spd_aes_cbc

    def capture(session_key, data):  # noqa: ANN001, ANN202
        out = original(session_key, data)
        try:
            _captured["spd"] = parsers.decode_plist(out)
        except Exception:  # noqa: BLE001 - never break the login for a diagnostic
            pass
        return out

    crypto.decrypt_spd_aes_cbc = capture


def checksum(sk: bytes, adsid: str, app: str = APP) -> bytes:
    return hmac.new(sk, b"apptokens" + adsid.encode() + app.encode(), hashlib.sha256).digest()


def decrypt_et(sk: bytes, et: bytes) -> dict:
    """The app-token blob: `"XYZ" + iv(16) + ciphertext + tag(16)`, AES-GCM with `sk`, `XYZ` as associated data."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: PLC0415

    if et[:3] != b"XYZ" or len(et) < 3 + 16 + 16:
        raise ValueError("unexpected et layout")
    iv, body, tag = et[3:19], et[19:-16], et[-16:]
    decryptor = Cipher(algorithms.AES(sk), modes.GCM(iv, tag)).decryptor()
    decryptor.authenticate_additional_data(et[:3])
    return parse_plain(decryptor.update(body) + decryptor.finalize())


_XML_HEADER = (b"<?xml version='1.0' encoding='UTF-8'?>"
               b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>")


def parse_plain(plain: bytes) -> dict:
    """The decrypted token blob. Like the login's `spd` it may be an XML plist WITHOUT its `<?xml` header, which
    `plistlib` refuses (`InvalidFileException`); the first real run met exactly that after the GCM tag had verified."""
    try:
        return plistlib.loads(plain)
    except plistlib.InvalidFileException:
        return plistlib.loads(_XML_HEADER + plain.lstrip())


def tokens_expiry(plain: dict, app: str = APP):  # noqa: ANN201
    return (plain.get("t") or {}).get(app, {}).get("expiry")


def save_token(path, token: str, adsid: str, expiry) -> None:  # noqa: ANN001
    """The Xcode app token is a credential for the developer API; 0600, and the file says when it was made."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump({"token": token, "adsid": adsid, "expiry": expiry,
                   "saved_at": datetime.now(timezone.utc).isoformat()}, stream)
    os.replace(tmp, path)


XCODE_CLIENT_INFO = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"


async def list_teams(account, token: str, adsid: str, say=print, *, client_info: str | None = XCODE_CLIENT_INFO,  # noqa: ANN001
                     identity_id: str | None = None) -> int:
    """One read-only `listTeams`. The developer API wants an **Xcode** client info; with the Anisette's own akd one it
    answers `resultCode 1100` "Your session has expired" even for a valid token (observed; the GSA endpoint is the
    opposite and needs akd). `client_info=None` keeps the Anisette's own, `identity_id` overrides the adsid."""
    headers = {
        **await account.get_anisette_headers(),
        "Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist", "Accept-Language": "en-us",
        "User-Agent": "Xcode", "X-Xcode-Version": "11.2 (11B41)",
        "X-Apple-App-Info": APP, "X-Apple-I-Identity-Id": identity_id or adsid, "X-Apple-GS-Token": token,
    }
    headers["X-Apple-I-Locale"] = headers.get("X-Apple-Locale", "en_US")
    if client_info:
        headers["X-MMe-Client-Info"] = client_info
    body = plistlib.dumps({"clientId": "XABBG36SBA", "protocolVersion": "QH65B2", "requestId": str(uuid.uuid4()).upper()})
    response = await account._http.post(DEV_URL, headers=headers, data=body)
    say(f"[dev] listTeams -> HTTP {response.status_code}")
    try:
        result = plistlib.loads(response.content)
    except Exception:  # noqa: BLE001
        say(f"[dev] not a plist; first bytes: {response.content[:120]!r}")
        return 1
    teams = result.get("teams")
    say(f"[dev] resultCode {result.get('resultCode')} {result.get('resultString') or ''}".rstrip()
        + f"; teams: {len(teams) if isinstance(teams, list) else 'none in the reply'}")
    # AltSign: a `teams` array in the reply is success; otherwise resultCode decides (0 = success).
    return 0 if isinstance(teams, list) or str(result.get("resultCode")) == "0" else 1


async def replay(account, path: str, say=print) -> int:  # noqa: ANN001
    """`listTeams` with a saved Xcode token and the saved login's machine: no login, no GSA request.

    Tries header variants, from the one that works to the ones that explained `resultCode 1100` ("Your session has expired"):
    The Xcode client info is the default now (it fixed `resultCode 1100`); the akd one is kept as the contrast, and the numeric
    DSID as an alternative identity id. One request each, stopping at the first success."""
    try:
        saved = json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        say(f"[dev] cannot read {path}: {type(error).__name__}")
        return 1
    token, adsid = saved["token"], saved["adsid"]
    say(f"[dev] saved token from {saved.get('saved_at')}, expiry {saved.get('expiry')}")
    dsid = str(getattr(account, "dsid", "") or "")
    variants = [("Xcode client info (the default)", {}),
                ("the Anisette's own client info (akd)", {"client_info": None})]
    if dsid and dsid != adsid:
        variants += [("numeric DSID as identity id", {"identity_id": dsid}),
                     ("Xcode client info + numeric DSID", {"client_info": XCODE_CLIENT_INFO, "identity_id": dsid})]
    worst = 1
    for name, extra in variants:
        say(f"[dev] variant: {name}")
        code = await list_teams(account, token, adsid, say, **extra)
        worst = min(worst, code)
        if code == 0:
            break
    return worst


async def run(account, say=print, app: str = APP, save: str | None = None) -> int:  # noqa: ANN001
    spd = _captured.get("spd")
    if not spd:
        say("[dev] no spd was captured from the login; nothing to do")
        return 1
    need = ("adsid", "GsIdmsToken", "sk", "c")
    say("[dev] spd carries: " + ", ".join(f"{k}={'yes' if k in spd else 'NO'}" for k in need))
    if any(k not in spd for k in need):
        say(f"[dev] spd keys present: {sorted(spd)}")
        return 1
    adsid, sk = spd["adsid"], spd["sk"]

    reply = await account._gsa_request({
        "app": [app], "c": spd["c"], "checksum": checksum(sk, adsid, app),
        "o": "apptokens", "t": spd["GsIdmsToken"], "u": adsid,
    })
    status = reply.get("Status") or {}
    say(f"[dev] apptokens {app}: ec {status.get('ec')} hsc {status.get('hsc')} {status.get('em') or ''}".rstrip())
    if status.get("ec") != 0:
        say("[dev] Apple refused the app-token request. This is the step where -22411 is reported "
            "(SideStore#1658, isideload#27): the machine passed login but not this.")
        return 1
    say("[dev] Apple ACCEPTED the app-token request")

    et = reply.get("et")
    if not isinstance(et, bytes):
        say(f"[dev] no encrypted token in the reply (keys: {sorted(k for k in reply if k != 'Status')})")
        return 0
    try:
        token = decrypt_et(sk, et)["t"][app]["token"]
    except Exception as error:  # noqa: BLE001
        say(f"[dev] the token could not be decrypted ({type(error).__name__}); verdict above stands, stopping")
        say(f"[dev] (et was {len(et)} bytes, starting {et[:3]!r}; InvalidTag would mean a wrong key or layout, "
            "other errors mean the cipher worked and the plaintext was unexpected)")
        return 0

    if save:
        save_token(save, token, adsid, tokens_expiry(decrypt_et(sk, et), app))
        say(f"[dev] the Xcode token was saved (0600, a credential): {save}")
    return await list_teams(account, token, adsid, say)
