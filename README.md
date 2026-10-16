# os-findmy: Apple login on Linux with an emulated Mac

This project logs in to an Apple Account on Linux. It gets the machine proof (Anisette data) from Apple's own macOS CoreADI library. The library runs under Unicorn emulation. No Mac is needed, and the machine is made up.

## Status

| Works | Not proven |
| --- | --- |
| Full login with SRP and 2FA (SMS or trusted device) | A saved token used later or from a second machine |
| Service tokens, including `searchPartyToken` | Real location reports from a tag (needs a tag key) |
| `acsnservice` accepts the token (`200`, empty result) | Anything about long-term use |

The key finding: Apple accepts a new machine for about **60 seconds** after provisioning. After that it refuses the machine with `-22421`. Earlier work blamed the identity, the library build and the model claim. They had no effect. See `EVIDENCE.md`.

## Quick start

You need Linux, Python 3.12 or later, `curl` and `7z`. Python 3.14 is tested.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest                 # offline tests
.venv/bin/python tools/fetch_mac_coreadi.py  # downloads iTunes 12.8.3 and unpacks CoreADI into ext/
tools/login.sh                               # enrol a machine and log in
```

`tools/login.sh` asks for the Apple ID and the password first, and then provisions the machine, so typing does not use up the 60 seconds. It then asks for the 2FA code. By default the code comes from a trusted Apple device. Use `--2fa sms` to get it by SMS to the first phone number. Have the device or phone in your hand before you start, because the code step must finish while the machine is still accepted.

## Test the token

Run the whole experiment with one command:

```bash
[FINDMY_KEY='<base64 private key>'] tools/flow_test.sh [--2fa device|sms]
```

The script does four things:

1. It enrols a fresh machine and logs in.
2. For 4 minutes, every 20 seconds, it sends one Find My request three ways: `live` (the logged-in session), `clean` (only the saved token) and `bad` (a changed token, the control).
3. It replays the saved token on a second machine that it enrols just now.
4. If `FINDMY_KEY` is set, it fetches location reports for that tag. Use the base64 private key of **your own** tag.

How to read the output:

| Output | Meaning |
| --- | --- |
| `bad` is `401` | The control works. A `200` elsewhere is meaningful. |
| `bad` is `200` | The endpoint accepts anything. The other results prove nothing. |
| `live` 200, `clean` 401 | The token needs the live session. |
| Both 200, then both 401 at about 70 s | The 60-second machine window also limits fetches. |
| Replay on the second machine gives `401` | The token belongs to the machine that logged in. |
| `[reports] count: N`, N above 0 | Real reports came back. This is the strong proof. |

The individual steps are `tools/login.sh [NAME] [--watch S] [--reports]`, `tools/replay_fresh.sh` and `tools/machoadi/replay.py`.

## How it works

1. The tool gets the URL bag from `gsa.apple.com` and starts the machine provisioning.
2. CoreADI makes a response from Apple's challenge. The tool sends it. Apple returns the provisioning data.
3. CoreADI makes a one-time code (OTP) and a machine ID. They go into the `X-Apple-I-MD` headers.
4. The tool does the SRP `init` and `complete` requests, then 2FA. Apple returns the tokens.

`MAC-ANISETTE-LOGIN.md` has the details and the error codes.

## Safety

- Use a **throwaway Apple Account**. Each login adds a fake Mac to the account's device list. Remove them after the tests.
- Apple rate-limits repeated logins with HTTP 429. Wait at least an hour, and do not retry in a loop.
- Apple allows one provisioning for each device ID. A second one returns HTTP 433. Use a new state name for each run.
- Never share state directories, session files, tokens, passwords, 2FA codes or tag keys. `tools/login.sh` writes the session to `/tmp/macadi/session-NAME.json` with mode 0600.

## Repository map

| Path | Content |
| --- | --- |
| `auth_probe.py` | Login, 2FA, token tests (`--macadi STATE`, `--sms`, `--watch`, `--reports`) |
| `tools/login.sh`, `flow_test.sh`, `replay_fresh.sh` | The scripts above |
| `tools/machoadi/` | Mach-O loader (`macho.py`), Unicorn harness (`harness.py`, `stubs.py`, `adi_run.py`), machine provisioning (`mac_anisette.py`, `gsa.py`), `findmy` provider, replay tool |
| `tools/fetch_mac_coreadi.py` | Downloads CoreADI from iTunes 12.8.3 |
| `EVIDENCE.md` | What we measured, and what is still open |
| `MAC-ANISETTE-LOGIN.md` | Procedure and error codes |

## What to report back

Share the `[watch]` lines, the replay lines, the `[reports]` line and any error text. Remove passwords, codes, tokens and keys first.
