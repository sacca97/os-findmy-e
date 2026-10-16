#!/usr/bin/env python3
"""Standalone FindMy authentication reproducer. No application imports or enrollment."""
import argparse
import asyncio
import getpass
import importlib.metadata
import json
import os
import platform
import shutil
import time
import sys
import plistlib
from pathlib import Path

from datetime import datetime, timezone

from findmy import AsyncAppleAccount, AsyncSmsSecondFactor, KeyPair, AsyncTrustedDeviceSecondFactor, LocalAnisetteProvider, LoginState, RemoteAnisetteProvider
from findmy.reports import account as account_module
from findmy.reports.anisette import BaseAnisetteProvider


def save_identity(account, directory):
    # Never persist the full account: FindMy includes its password and service tokens.
    try:
        state = account.to_json()
    except NotImplementedError:
        # A provider whose state directory is the saved identity (the Mac CoreADI one)
        # has nothing to serialize, and needs nothing restored: `make_mac_account`
        # rebuilds the account from that directory on every run.
        return
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / "identity.json"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
        json.dump({"ids": state["ids"], "anisette": state["anisette"]}, stream)
    path.chmod(0o600)


def make_account(url, directory):
    path = directory / "identity.json"
    saved = json.loads(path.read_text()) if path.exists() else None
    if saved:
        mapping = saved["anisette"]
        expected = "aniRemote" if url else "aniLocal"
        if mapping["type"] != expected or (url and mapping["url"] != url):
            raise ValueError("Use a different --state-dir when changing Anisette providers")
        provider = (RemoteAnisetteProvider.from_json(mapping) if url
                    else LocalAnisetteProvider.from_json(mapping))
    else:
        provider = RemoteAnisetteProvider(url, timeout=30) if url else LocalAnisetteProvider()
    return AsyncAppleAccount(provider, timeout=30, **(saved["ids"] if saved else {}))


def make_mac_account(state):
    """The account as the machine our own CoreADI provisioning already registered.

    The emulator introduced this identity to Apple's MidService (one client info, one
    device id, one local user id) and the OTP is only meaningful for it, so the login has
    to be that same installation and not a second device beside it: `uid`/`devid` are read
    from the same identity.json the headers are built from.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent / "tools" / "machoadi"))
    from provider import MacAnisetteProvider
    provider = MacAnisetteProvider(state)
    identity = provider.identity_json
    print("[macadi] state:", state, "platform:", provider.identity.platform, flush=True)
    return AsyncAppleAccount(provider, timeout=30,
                             uid=identity["local_user_uuid"], devid=identity["device_id"])


def with_client_info(url, headers, client_info):
    """Replace any X-MMe-Client-Info header (any capitalisation); the library sends a Mac identity beside
    the Android Anisette, which Apple refuses. Names only are printed."""
    replaced = False
    result = {}
    for name, value in headers.items():
        if name.lower() == "x-mme-client-info":
            value, replaced = client_info, True
        result[name] = value
    if replaced:
        print("[override] X-Mme-Client-Info ->", url.rsplit("/", 1)[-1], flush=True)
    return result


def describe_delegates(response):
    """Print the structure of a loginDelegates reply: key names and status fields only, no token values."""
    try:
        data = response.plist()
    except Exception as error:  # noqa: BLE001 - diagnostics only
        print("[delegates] reply is not a plist:", type(error).__name__)
        return
    delegates = data.get("delegates") or {}
    print("[delegates]", json.dumps({
        "top_keys": sorted(data), "status": data.get("status"),
        "localizedError": data.get("localizedError"), "description": data.get("description"),
        "delegates": {name: {"status": d.get("status"), "status-message": d.get("status-message"),
                             "service-data keys": sorted((d.get("service-data") or {})),
                             "token names": sorted(((d.get("service-data") or {}).get("tokens") or {}))}
                      for name, d in delegates.items()}}, default=str), flush=True)


def machine_born(state):
    """Unix time the machine was provisioned (identity.json). Not the store's mtime: every OTP rewrites it."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / "tools" / "machoadi"))
    from mac_anisette import provisioned_at
    return provisioned_at(state)


def trace_requests(account, client_info=None, born=None):
    post = account._http.post
    request = account._gsa_request

    async def traced_post(url, **kwargs):
        if url == account._ENDPOINT_GSA:
            body = plistlib.loads(kwargs["data"])["Request"]
            cpd = body["cpd"]
            headers = kwargs["headers"]
            if client_info:
                headers = kwargs["headers"] = {**headers, "X-MMe-Client-Info": client_info}
            print("[request]", json.dumps({
                "operation": body.get("o"),
                # Seconds since the machine was provisioned: the machine is only accepted for a short
                # time, and the request after the 2FA code is the one a slow human can push past it.
                **({"machine_age_s": round(time.time() - born)} if born else {}),
                "client_info": headers.get("X-MMe-Client-Info"),
                "user_agent": headers.get("User-Agent"),
                "client_time": cpd.get("X-Apple-I-Client-Time"),
                "timezone": cpd.get("X-Apple-I-TimeZone"),
                "locale": cpd.get("X-Apple-Locale"),
                "routing": cpd.get("X-Apple-I-MD-RINFO"),
                "header_lengths": {key: len(str(cpd.get(key) or "")) for key in (
                    "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Mme-Device-Id")},
            }), flush=True)
        elif client_info:
            kwargs["headers"] = with_client_info(url, kwargs.get("headers", {}), client_info)
        response = await post(url, **kwargs)
        if url.endswith("/loginDelegates"):
            describe_delegates(response)
        return response

    async def traced_request(parameters):
        response = await request(parameters)
        status = response.get("Status") or {}
        print("[GSA]", json.dumps({"operation": parameters.get("o"), "ec": status.get("ec"),
              "em": status.get("em"), "hsc": status.get("hsc"), "au": status.get("au")}), flush=True)
        if parameters.get("o") == "complete" and status.get("hsc") == 409 and not status.get("au"):
            # Since 2026-10-12 Apple pushes the 2FA prompt itself: hsc 409 and no "au"
            # (SideSign#5, FindMy.py#278). Without this the library skips 2FA and mobileme answers status=1.
            status["au"] = "trustedDeviceSecondaryAuth"
            print("[note] hsc 409 without au: treating as trusted-device 2FA", flush=True)
        return response

    request_method = getattr(account._http, "request", None)

    async def traced_request_method(method, url, **kwargs):
        # 2FA and other calls go through request(), not post(); keep their identity consistent too
        if client_info:
            kwargs["headers"] = with_client_info(url, kwargs.get("headers", {}), client_info)
        return await request_method(method, url, **kwargs)

    account._http.post = traced_post
    if request_method:
        account._http.request = traced_request_method
    account._gsa_request = traced_request


FETCH_BODIES = {
    # empty id lists: a token the server accepts gets a validation/empty answer, a rejected token gets 401
    "https://gateway.icloud.com/findmyservice/v2/fetch": {
        "clientContext": {"clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent", "policy": "foregroundClient"},
        "fetch": [{"ownedDeviceIds": [], "keyType": 1, "primaryIds": [], "secondaryIds": []}]},
    "https://gateway.icloud.com/acsnservice/fetch": {
        "context": {"policy": "foregroundClient", "clientBundleIdentifier": "com.apple.icloud.searchpartyd"},
        "search": [{"ids": [], "secondaryIds": []}]},
}


async def probe_fetch(account, client_info):
    """One request per endpoint with each token we hold, to tell 'token rejected' from 'nothing to return'."""
    tokens = account._login_state_data.get("mobileme_data", {}).get("tokens", {})
    for token_name in sorted(tokens):
        for url, body in FETCH_BODIES.items():
            headers = await account.get_anisette_headers()
            if client_info:
                headers = {**headers, "X-MMe-Client-Info": client_info}
            response = await account._http.post(url, auth=(account.dsid, tokens[token_name]), headers=headers, json=body)
            print("[fetch-probe]", json.dumps({
                "token": token_name, "endpoint": url.rsplit("/", 2)[-2], "status": response.status_code,
                "bytes": len(response.content),
                "www-authenticate": dict(response.headers).get("WWW-Authenticate")}), flush=True)


def _age(machine_state):
    """Age of the machine in seconds, for messages; '?' when there is no machine directory."""
    try:
        return round(time.time() - machine_born(machine_state))
    except (OSError, ValueError, TypeError):
        return "?"


async def watch_token(account, state, token, seconds, interval=10, other_after=40):
    """Send the same acsnservice request every `interval` s by several routes, to tell what ends the window.

    live  -- the logged-in account object: its HTTP client keeps whatever the login left behind.
    clean -- a new account on the same machine with only the saved token, like `replay.py`.
    bad   -- negative control: `clean` with the token altered. It must be 401.
    other -- a second machine, provisioned once the first has been alive `other_after` s, sending the
             same token with its own headers. 200 here, after the first machine has lapsed, means the
             token outlives its machine and only the machine's headers expire; 401 means the token
             dies with (or is bound to) the machine that logged in.
    The machine's age is printed with each row.
    """
    import subprocess
    import time
    url = "https://gateway.icloud.com/acsnservice/fetch"
    cli = Path(__file__).resolve().parent / "tools" / "machoadi" / "mac_anisette.py"

    def born_of(directory):
        return machine_born(directory)

    born = born_of(state)
    clean = make_mac_account(state)
    other, other_born = None, None
    try:
        end = time.time() + seconds
        while time.time() < end:
            if other is None and time.time() - born >= other_after:
                directory = Path(str(state) + "-b")
                shutil.rmtree(directory, ignore_errors=True)
                subprocess.run([sys.executable, str(cli), "provision", "--state", str(directory)],
                               check=True, capture_output=True, text=True, timeout=120)
                other, other_born = make_mac_account(directory), born_of(directory)
            routes = [("live", account, token), ("clean", clean, token),
                      ("bad", clean, token[:-1] + ("A" if token[-1] != "A" else "B"))]
            if other is not None:
                routes.append(("other", other, token))
            row = []
            for label, acct, tok in routes:
                headers = await acct.get_anisette_headers()
                response = await acct._http.post(url, auth=(account.dsid, tok), headers=headers,
                                                 json=FETCH_BODIES[url])
                row.append(f"{label} {response.status_code}")
            other_age = f"   (other machine age {time.time() - other_born:3.0f} s)" if other is not None else ""
            print(f"[watch] machine age {time.time() - born:5.0f} s   " + "   ".join(row) + other_age,
                  flush=True)
            await asyncio.sleep(interval)
    finally:
        await clean.close()
        if other is not None:
            await other.close()


async def run_restored(account, state, resyncer=None, after_login=None, needs_password=True):
    """Use a saved login: no password prompt at login, no 2FA. One request first, to see that it still holds."""
    try:
        state_value = account._login_state
        print(f"[restore] login state {state_value.name}, machine age {_age(state)} s", flush=True)
        if state_value != LoginState.LOGGED_IN:
            print("[restore] the saved login is not complete; log in again (tools/aged_login.sh)")
            return 1
        if resyncer is not None and getattr(resyncer, "preflight", False):
            outcome = await resyncer.ensure_fresh()
            print(f"[resync] preflight at machine age {resyncer.age()} s -> {outcome}", flush=True)
            if outcome not in ("accepted", "revived"):
                print("[restore] the machine is not accepted; nothing more was sent")
                return 1
            account._anisette._window = None
        url = "https://gateway.icloud.com/acsnservice/fetch"
        token = account._login_state_data.get("mobileme_data", {}).get("tokens", {}).get("searchPartyToken")
        if not token:
            print("[restore] the saved login holds no searchPartyToken; log in again")
            return 1
        response = await account._http.post(url, auth=(account.dsid, token), headers=await account.get_anisette_headers(),
                                            json=FETCH_BODIES[url])
        print(f"[restore] token check: acsnservice -> {response.status_code}", flush=True)
        if response.status_code != 200:
            print("[restore] the token is no longer accepted; log in again (tools/aged_login.sh)")
            return 1
        if after_login is not None:
            if needs_password and not account._password:
                account._password = getpass.getpass("Apple ID password (this saved login has none; needed once "
                                                    "to renew the escrow token): ")
            return await after_login(account) or 0
        return 0
    finally:
        await account.close()


def install_auto_resync(account, resyncer):
    """Answer Apple's resync inside the login: a GSA reply of hsc 434 with a SIM is synchronised,
    posted to syncMachine, and the same request is sent once more with a fresh OTP."""
    inner = account._gsa_request

    def forget_cached_otp():
        account._anisette._window = None  # the provider caches headers per 30 s window

    resyncer.on_synced = forget_cached_otp

    async def resyncing(parameters):
        response = await inner(parameters)
        status = response.get("Status") or {}
        sim = status.get("X-Apple-I-MD-DATA")
        if status.get("hsc") == 434 and sim:
            print(f"[resync] {parameters.get('o')} answered 434 at machine age {resyncer.age()} s: answering it",
                  flush=True)
            answered = await resyncer.answer_sim(sim)
            if answered["ok"]:
                forget_cached_otp()
                response = await inner(parameters)
                print("[resync] retried:", (response.get("Status") or {}).get("ec"), flush=True)
        return response

    account._gsa_request = resyncing


async def _resync_before_submit(resyncer, account):
    """The code is typed; a late second `complete` is answered -22406 (not 434), so renew first."""
    if resyncer is None or not getattr(resyncer, "preflight", False):
        return
    outcome = await resyncer.ensure_fresh()
    print(f"[resync] before 2FA submit, machine age {resyncer.age()} s -> {outcome}", flush=True)
    account._anisette._window = None


async def authenticate(account, directory, client_info=None, sms=None, save_session=None, reports=False,
                       watch=0, machine_state=None, watch_interval=10, watch_other_after=40,
                       request_push=False, resyncer=None, after_login=None, save_login=None,
                       keep_password=True):
    try:
        save_identity(account, directory)
        # tools/login.sh asks for these *before* it provisions the machine and passes them in the
        # environment, so no typing time is spent inside the machine's 60 s window.
        email = os.environ.pop("APPLE_ID", None) or input("Apple ID: ").strip()
        password = os.environ.pop("APPLE_PASSWORD", None) or getpass.getpass("Password: ")
        if resyncer is not None and getattr(resyncer, "preflight", False):
            # Preflight: do not spend a password attempt on a machine Apple would refuse.
            outcome = await resyncer.ensure_fresh()
            print(f"[resync] preflight at machine age {resyncer.age()} s -> {outcome}", flush=True)
            if outcome not in ("accepted", "revived"):
                raise SystemExit(f"preflight: the machine is not accepted ({outcome}); no login was attempted")
            account._anisette._window = None
        try:
            state = await account.login(email, password)
        finally:
            del password
        if state == LoginState.REQUIRE_2FA:
            # What Apple says it will do, so a missing code can be told from a request never made.
            info = getattr(account, "_account_info", None) or {}
            print("[2fa] Apple offers:", "a trusted-device code" if info.get("trusted_device_2fa")
                  else "no trusted-device code (SMS only)", flush=True)
        if state == LoginState.REQUIRE_2FA and sms is not None:
            # SMS instead of the trusted-device push, for an account whose devices show no prompt.
            # Ask for the code only after the request is sent, so the window since provisioning is
            # spent on the network and not on typing.
            phones = [m for m in await account.get_2fa_methods() if isinstance(m, AsyncSmsSecondFactor)]
            print("phone numbers:", [(i, m.phone_number) for i, m in enumerate(phones)], flush=True)
            method = phones[sms]
            await method.request()
            print(f"SMS requested for number {sms}.", flush=True)
            print(f"[2fa] the machine is {_age(machine_state)} s old; type the code at once.", flush=True)
            code = input("SMS code: ").strip()
            await _resync_before_submit(resyncer, account)
            state = await method.submit(code)
        elif state == LoginState.REQUIRE_2FA:
            # get_2fa_methods() also fetches the SMS page, which can fail with 401 if the machine's window has lapsed.
            # Use the trusted-device push method directly; no SMS request is ever sent.
            method = AsyncTrustedDeviceSecondFactor(account)
            if request_push:
                # The prompt does not arrive on its own at the 409 (observed 2026-10-16), so it is asked for
                # by default; this reports what Apple answered.
                try:
                    await method.request()
                    print("[2fa] push requested: accepted by Apple", flush=True)
                except Exception as error:  # noqa: BLE001 - report, then still wait for a code
                    print(f"[2fa] push request failed: {type(error).__name__}: {error}", flush=True)
            # No method.request(): Apple already pushed the prompt when "complete" returned hsc 409,
            # and the extra td_2fa_request GET fails with 401 (seen 2026-10-14).
            print("Apple has pushed a prompt to your other devices. Tap Allow, then enter the code.")
            print(f"[2fa] the machine is {_age(machine_state)} s old; the code must be accepted within about "
                  "40 s of provisioning, so type it as soon as you have it.", flush=True)
            code = input("2FA code: ").strip()
            await _resync_before_submit(resyncer, account)
            state = await method.submit(code)
        print("Login state:", state.name)
        if state == LoginState.LOGGED_IN:
            tokens = account._login_state_data.get("mobileme_data", {}).get("tokens", {})
            print("mobileme token names (no values):", sorted(tokens))
            await probe_fetch(account, client_info)
            if save_session:
                # Only the Find My token and the dsid: enough to replay acsnservice, nothing more.
                path = Path(save_session)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as stream:
                    json.dump({"dsid": account.dsid, "searchPartyToken": tokens["searchPartyToken"],
                               "saved_at": datetime.now(timezone.utc).isoformat()}, stream)
                print("session saved (0600):", path, flush=True)
            if watch:
                await watch_token(account, machine_state, tokens["searchPartyToken"], watch, watch_interval,
                                  watch_other_after)
            if save_login:
                sys.path.insert(0, str(Path(__file__).resolve().parent / "tools" / "machoadi"))
                import login_store
                login_store.save(account, save_login, keep_password=keep_password)
                print(f"[login] saved (0600, {'with' if keep_password else 'WITHOUT'} the password): {save_login}"
                      "  -- it is a credential; delete it when done", flush=True)
            if after_login is not None:
                code = await after_login(account)
                if code:
                    return code
            if reports:
                # The private key comes from the environment so it is in no argv and no file.
                key = KeyPair.from_b64(os.environ["FINDMY_KEY"])
                found = await account.fetch_location_history(key)
                print("[reports] count:", len(found), flush=True)
                if found:
                    newest = max(found, key=lambda r: r.timestamp)
                    print("[reports] newest:", newest.timestamp.isoformat(),
                          round(newest.latitude, 3), round(newest.longitude, 3), flush=True)
        return 0 if state == LoginState.LOGGED_IN else 1
    finally:
        try:
            save_identity(account, directory)
        finally:
            await account.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anisette-url", help="remote V1-compatible JSON endpoint; default is local")
    parser.add_argument("--state-dir", type=Path, default=Path(".state"))
    parser.add_argument("--plain-z-timestamp", action="store_true",
                        help="experiment: send client time as ...Z instead of ...+00:00Z")
    parser.add_argument("--consistent-user-agent", action="store_true",
                        help="experiment: derive the GSA User-Agent from the client-info identity")
    parser.add_argument("--client-info", help="experiment: replace X-MMe-Client-Info on GSA requests "
                        "(SideSign#5 reports an Android string matching the Android ADI works)")
    parser.add_argument("--sms", nargs="?", const=0, type=int, metavar="INDEX",
                        help="on 2FA, request an SMS code to the INDEXth phone number (default 0) instead of "
                        "waiting for the trusted-device push")
    parser.add_argument("--save-session", metavar="FILE",
                        help="after login, save the dsid and searchPartyToken to FILE (mode 0600)")
    parser.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                        help="after login, for SECONDS, send the acsnservice request every 10 s through the live "
                        "account and through a clean one holding only the token (needs --macadi)")
    parser.add_argument("--watch-interval", type=int, default=10, metavar="SECONDS",
                        help="seconds between --watch requests (default 10)")
    parser.add_argument("--watch-other-after", type=int, default=40, metavar="SECONDS",
                        help="during --watch, provision a second machine once the first is SECONDS old and "
                        "send the same token with its headers (default 40)")
    parser.add_argument("--request-push", action="store_true",
                        help="(now the default) on 2FA by trusted device, ask Apple to send the prompt and "
                        "print its answer")
    parser.add_argument("--no-request-push", action="store_true",
                        help="on 2FA by trusted device, do NOT ask for the prompt; rely on Apple's own push at "
                        "the 409, which in practice does not arrive")
    parser.add_argument("--reports", action="store_true",
                        help="after login, fetch location reports for the private key in $FINDMY_KEY (base64)")
    parser.add_argument("--auto-resync", action="store_true",
                        help="with --macadi: answer Apple's resync (hsc 434) so an AGED machine can log in: a "
                        "preflight before the password is used, a renewal right before the 2FA code is "
                        "submitted, and any 434 during the login (see tools/machoadi/resync.py)")
    parser.add_argument("--preflight", action="store_true",
                        help="with --auto-resync: also check the machine with a credential-free init before the "
                        "login and before the 2FA submit (costs 1-3 Apple requests each; off by default now that "
                        "the real clock keeps the machine accepted -- a 434 during the login is still answered)")
    parser.add_argument("--ignore-cooldown", action="store_true", help="skip the shared 429 cooldown guard")
    parser.add_argument("--save-login", metavar="FILE",
                        help="after a successful login, save the account state (service tokens and, unless "
                        "--no-save-password, the password) to FILE, mode 0600. It is a credential.")
    parser.add_argument("--no-save-password", action="store_true", help="with --save-login: leave the password out")
    parser.add_argument("--restore-login", metavar="FILE",
                        help="with --macadi: use a login saved by --save-login instead of logging in "
                        "(no password prompt, no 2FA)")
    parser.add_argument("--tags", action="store_true",
                        help="after login: read the keychain (asks which device's screen-lock passcode to use), "
                        "decrypt your tags from the account and fetch their locations; read-only, never joins "
                        "the keychain circle (tools/machoadi/tag_keys.py)")
    parser.add_argument("--dev-check", action="store_true",
                        help="after a fresh login: the app-token request and one read-only developer call "
                        "(listTeams), the steps sideloading tools need (tools/machoadi/dev_check.py)")
    parser.add_argument("--dev-save", metavar="FILE",
                        help="with --dev-check: save the Xcode app token (0600, a credential) so --dev-from can "
                        "reuse it without a new login")
    parser.add_argument("--dev-from", metavar="FILE",
                        help="with --restore-login: call listTeams with a token saved by --dev-save, trying the "
                        "header variants that could explain 'session expired'. No login, no GSA request")
    parser.add_argument("--tags-from", metavar="FILE",
                        help="with --restore-login: fetch the locations of the accessories saved by --tags-save. "
                        "No keychain, no escrow, no passcode")
    parser.add_argument("--tags-list", action="store_true",
                        help="with --tags: only list the recoverable escrow records; no passcode is requested")
    parser.add_argument("--tags-save", metavar="FILE", help="with --tags: save the decrypted accessories (0600)")
    parser.add_argument("--macadi", type=Path, metavar="STATE",
                        help="log in with the Mac CoreADI emulator in STATE (see tools/machoadi/mac_anisette.py): "
                        "OTP/machine ID/routing come from the genuine Mac framework under Unicorn, and uid/devid "
                        "are the pair that STATE provisioned")
    args = parser.parse_args()
    if args.restore_login and not args.macadi:
        parser.error("--restore-login needs --macadi")
    if args.dev_save and not args.dev_check:
        parser.error("--dev-save needs --dev-check")
    if args.dev_from and not args.restore_login:
        parser.error("--dev-from needs --restore-login (tools/restored_run.sh)")
    if args.dev_from and (args.dev_check or args.tags or args.tags_from):
        parser.error("--dev-from is its own mode; use it alone")
    if args.dev_check and args.restore_login:
        parser.error("--dev-check needs a fresh login: the app token is signed with the login's session key, "
                     "which a saved login does not keep")
    if args.tags_from and not args.restore_login:
        parser.error("--tags-from needs --restore-login (tools/restored_run.sh)")
    if args.tags_from and args.tags:
        parser.error("--tags-from and --tags are different routes; use one")
    if (args.tags_list or args.tags_save) and not args.tags:
        parser.error("--tags-list/--tags-save need --tags")
    if args.auto_resync and not args.macadi:
        parser.error("--auto-resync needs --macadi")
    if args.macadi:
        sys.path.insert(0, str(Path(__file__).resolve().parent / "tools" / "machoadi"))
        import cooldown
        cooldown.guard(args.ignore_cooldown)
    if args.macadi and args.anisette_url:
        parser.error("--macadi supplies its own Anisette: drop --anisette-url")
    if args.plain_z_timestamp:
        BaseAnisetteProvider.timestamp = property(lambda self: datetime.now(tz=timezone.utc)
                                                  .replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"))
    print("Python:", platform.python_version(), "OS:", platform.platform(),
          "architecture:", platform.machine())
    print("Versions:", {name: importlib.metadata.version(name)
                        for name in ("FindMy", "Anisette", "aiohttp", "unicorn")})
    metadata = importlib.metadata.distribution("FindMy").read_text("direct_url.json")
    print("FindMy commit:", (json.loads(metadata).get("vcs_info", {}).get("commit_id")
                             if metadata else "PyPI release"))
    try:
        async def run():
            if args.restore_login:
                import login_store
                account = login_store.restore(args.macadi, args.restore_login)
                print("[macadi] state:", args.macadi, "(restored login)", flush=True)
            else:
                account = make_mac_account(args.macadi) if args.macadi else make_account(args.anisette_url, args.state_dir)
            client_info = args.client_info
            if args.consistent_user_agent:
                account_module._GSA_USER_AGENT = account._anisette.akd_user_agent
            trace_requests(account, client_info, machine_born(args.macadi) if args.macadi else None)
            after_login = None
            if args.tags:
                from tag_keys import run as run_tags

                async def after_login(logged_in):
                    return await run_tags(logged_in, list_only=args.tags_list, save=args.tags_save)
            if args.tags_from:
                from tag_keys import fetch_saved

                async def after_login(logged_in):
                    return await fetch_saved(logged_in, args.tags_from)
            if args.dev_check:
                import dev_check

                dev_check.install_spd_capture()  # before the login: the final spd is only visible while it runs
                previous = after_login

                async def after_login(logged_in):
                    code = await dev_check.run(logged_in, save=args.dev_save)
                    if previous is not None:
                        code = await previous(logged_in) or code
                    return code
            if args.dev_from:
                import dev_check

                async def after_login(logged_in):
                    return await dev_check.replay(logged_in, args.dev_from)
            resyncer = None
            if args.auto_resync:
                from resync import Resyncer
                resyncer = Resyncer(args.macadi)
                resyncer.preflight = args.preflight
                install_auto_resync(account, resyncer)
            if args.restore_login:
                return await run_restored(account, args.macadi, resyncer, after_login, needs_password=not (args.tags_from or args.dev_from))
            return await authenticate(account, args.state_dir, client_info, args.sms,
                                      args.save_session, args.reports, args.watch, args.macadi,
                                      args.watch_interval, args.watch_other_after, not args.no_request_push,
                                      resyncer, after_login, args.save_login, not args.no_save_password)
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"Authentication stopped: {type(error).__name__}: {error}")
        if args.macadi:
            import cooldown
            if cooldown.looks_like_429(error):
                cooldown.note_429()
                print(f"[cooldown] 429 recorded: nothing in this repo will talk to Apple for "
                      f"{cooldown.COOLDOWN_MINUTES} minutes", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
