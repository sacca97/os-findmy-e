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


def trace_requests(account, client_info=None):
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
        return max(p.stat().st_mtime for p in (Path(directory) / "store").glob("adi*.pb"))

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


async def authenticate(account, directory, client_info=None, sms=None, save_session=None, reports=False,
                       watch=0, machine_state=None, watch_interval=10, watch_other_after=40):
    try:
        save_identity(account, directory)
        email = input("Apple ID: ").strip()
        password = getpass.getpass("Password: ")
        try:
            state = await account.login(email, password)
        finally:
            del password
        if state == LoginState.REQUIRE_2FA and sms is not None:
            # SMS instead of the trusted-device push, for an account whose devices show no prompt.
            # Ask for the code only after the request is sent, so the window since provisioning is
            # spent on the network and not on typing.
            phones = [m for m in await account.get_2fa_methods() if isinstance(m, AsyncSmsSecondFactor)]
            print("phone numbers:", [(i, m.phone_number) for i, m in enumerate(phones)], flush=True)
            method = phones[sms]
            await method.request()
            print(f"SMS requested for number {sms}.", flush=True)
            state = await method.submit(input("SMS code: ").strip())
        elif state == LoginState.REQUIRE_2FA:
            # get_2fa_methods() also fetches the SMS page, which can fail with 401 if the machine's window has lapsed.
            # Use the trusted-device push method directly; no SMS request is ever sent.
            method = AsyncTrustedDeviceSecondFactor(account)
            # No method.request(): Apple already pushed the prompt when "complete" returned hsc 409,
            # and the extra td_2fa_request GET fails with 401 (seen 2026-10-14).
            print("Apple has pushed a prompt to your other devices. Tap Allow, then enter the code.")
            state = await method.submit(input("2FA code: ").strip())
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
    parser.add_argument("--reports", action="store_true",
                        help="after login, fetch location reports for the private key in $FINDMY_KEY (base64)")
    parser.add_argument("--macadi", type=Path, metavar="STATE",
                        help="log in with the Mac CoreADI emulator in STATE (see tools/machoadi/mac_anisette.py): "
                        "OTP/machine ID/routing come from the genuine Mac framework under Unicorn, and uid/devid "
                        "are the pair that STATE provisioned")
    args = parser.parse_args()
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
            account = make_mac_account(args.macadi) if args.macadi else make_account(args.anisette_url, args.state_dir)
            client_info = args.client_info
            if args.consistent_user_agent:
                account_module._GSA_USER_AGENT = account._anisette.akd_user_agent
            trace_requests(account, client_info)
            return await authenticate(account, args.state_dir, client_info, args.sms,
                                      args.save_session, args.reports, args.watch, args.macadi,
                                      args.watch_interval, args.watch_other_after)
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"Authentication stopped: {type(error).__name__}: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
