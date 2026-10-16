# os-findmy: Apple login on Linux with an emulated Mac

This project logs in to an Apple Account on Linux. It gets the machine proof (Anisette data) from Apple's own macOS CoreADI library. The library runs under Unicorn emulation. No Mac is needed, and the machine is made up.

## In short

Apple's login and Find My services expect every request to carry **Anisette data**: a set of headers (`X-Apple-I-MD`, `X-Apple-I-MD-M` and others) that proves the request comes from an Apple machine that registered itself with Apple. On a real Mac a system library, **CoreADI**, makes them. This project runs that same library on Linux under the Unicorn CPU emulator, registers a **made-up Mac** with Apple, and then uses it to:

1. log in to an Apple Account (password, then 2FA) and get service tokens;
2. replay the Find My token with that machine's headers;
3. read the keys of your own tags out of your iCloud account, and fetch and decrypt their location reports.

It does not break anything: the account password, the 2FA code and (for tag keys) a device passcode are all required. It only replaces the Mac. Use your own account and your own tags.

## Status

| Works | Not shown yet |
| --- | --- |
| Full login with SRP and 2FA (trusted-device push or SMS) | A real location report from a tag |
| Service tokens, including `searchPartyToken` | Creating certificates, App IDs or profiles, or installing an app; a longer test (hours or days); more than one account or machine |
| A fresh machine is accepted for at least 4 minutes (credential-free probe, real clock) | How long a machine and a token last beyond about 30 minutes |
| `acsnservice` accepts the token with its own machine's headers 16 minutes after provisioning (`200`, bad-token control `401`) | Whether the token survives hours or days |
| A login on a machine 29 minutes old completed and asked for no second 2FA (seen once) | |
| Saving a login and restoring it later with no login and no 2FA | Restoring after the tokens have aged |
| The sideloading read path: the Xcode app token and the developer API's `listTeams` (1 team returned) | |
| Answering Apple's resync (`hsc 434`) turns a refused machine into an accepted one (`resync.py`, seen once) | |

**The key finding.** For days the machine was accepted for only about a minute after provisioning and then refused with `-22421`. The cause was in our emulation, not in Apple's rules: CoreADI's clock was frozen at one date, so the one-time code (OTP) never changed. With the real clock a fresh machine is still accepted after 4 minutes, a token still works at 16 minutes, and a login at 29 minutes completed. Apple's resync handshake (the `-22421` / `hsc 434` answer and the SRM reply) also works; it is the repair path if a machine does lapse. The real clock is the default now. `ADI_FROZEN_TIME=1` brings the old behaviour back. See `EVIDENCE.md`, sections 6 to 9.

## Quick start

You need Linux, Python 3.12 or later, `curl` and `7z`. Python 3.14 is tested.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest                 # offline tests
.venv/bin/python tools/fetch_mac_coreadi.py  # downloads iTunes 12.8.3 and unpacks CoreADI into ext/
tools/login.sh NAME                          # make a machine and log in
```

`tools/login.sh` asks for the Apple ID and the password first, then provisions the machine, then asks for the 2FA code. By default the code comes from a trusted Apple device, and the push prompt is requested for you. Use `--2fa sms` to get the code by SMS instead. The state goes to `/tmp/macadi/NAME`.

To log in again on a machine that already exists, with the login saved for later:

```bash
tools/aged_login.sh /tmp/macadi/NAME [--2fa device|sms]
```

This writes `/tmp/macadi/NAME-login.json` (see **Saved logins** below) and `/tmp/macadi/NAME-session.json`.

## Saved logins

`tools/aged_login.sh` saves the login by default. `tools/restored_run.sh` uses it with **no Apple ID prompt, no password prompt and no 2FA code**:

```bash
tools/restored_run.sh /tmp/macadi/NAME [--tags ...]
```

It first sends one request with the saved token to see that it still works. If Apple refuses it, the script says so and tells you to log in again.

**The saved file is a credential.** It holds the service tokens and, unless you pass `--no-save-login` (or `--no-save-password` to `auth_probe.py`), your Apple ID password in clear text, with mode 0600. It only works with the machine that made it: a file saved on a different machine is refused. Delete it when you are done: `rm /tmp/macadi/NAME-login.json`.

## Test the token

Replay the saved token with the machine that logged in. Do not use a new machine: a token only works with the headers of the machine that made it.

```bash
tools/replay_aged.sh /tmp/macadi/NAME 12 30 0     # 12 requests, 30 s apart, no resync
tools/replay_aged.sh /tmp/macadi/NAME 12 30 45    # with a resync every 45 s
```

Each line shows the machine age (seconds since provisioning), the status and a bad-token control, which must be `401`. For any answer other than `200` it prints Apple's headers and the start of the body, and says whether the answer carries a resync request.

| Output | Meaning |
| --- | --- |
| Control `401`, everything else `200` | The `200` values are real. |
| Control `200` | The endpoint accepts anything. The other results prove nothing. |
| `200`, then `401` at some age | The machine lapsed at that age. Note it. |
| `401` from the first line | The token itself is refused. |

`tools/flow_test.sh` is the older all-in-one experiment (fresh machine, login, watch, replay on a second machine). `tools/machoadi/age_check.py` asks `init` at growing ages with a synthetic account and no login.

## Your tags

There are two ways to get a tag's location. Use only tags that you own.

**With a key you already have** (for example exported from a Mac), the base64 private key of the tag:

```bash
tools/fetch_tag.sh /tmp/macadi/NAME --dry-run     # checks the inputs, sends nothing
tools/fetch_tag.sh /tmp/macadi/NAME --summary     # counts only
tools/fetch_tag.sh /tmp/macadi/NAME               # the last 20 decrypted reports
```

**With the key from the account.** Apple stores the tag keys end-to-end encrypted in CloudKit, protected by iCloud Keychain keys. `tools/machoadi/tag_keys.py` reads them with the library's read-only path. It needs the **screen-lock passcode of one of your devices** (PIN or Mac login password), and it does not join the keychain circle:

```bash
tools/aged_login.sh /tmp/macadi/NAME --tags --tags-list    # login once; lists recoverable devices; no passcode
tools/restored_run.sh /tmp/macadi/NAME --tags --tags-save /tmp/macadi/NAME-tags.json
```

The second command lists the devices (with one device it picks it for you; with several it asks which) and asks for the passcode, once. A wrong passcode is **never retried**, because Apple limits wrong guesses on a device's escrow record. `--tags-save` writes the decrypted tags (their master keys are secrets) with mode 0600. Later fetches then need no passcode, no keychain and no escrow:

```bash
tools/restored_run.sh /tmp/macadi/NAME --tags-from /tmp/macadi/NAME-tags.json
```

This route ran to the end once, on one account: it listed the account's iPhone and a third-party "Smart Tracker" paired through Find My, decrypted both, and the tracker returned 8 location reports (the iPhone returned none). Delete the tags file when you are done: it holds the tags' master keys.

## Glossary

| Term | Meaning |
| --- | --- |
| Anisette data | The machine-proof headers described above. Made by CoreADI from the machine's state and the clock |
| CoreADI / ADI | Apple's library that makes Anisette data. We run the macOS build (iTunes 12.8.3, version 4.19) under emulation |
| Provisioning | The one-time registration of a machine with Apple. Apple sends a challenge (SPIM), CoreADI answers (CPIM), Apple returns the machine's credentials (PTM and TK) |
| MID and OTP | Machine ID and one-time code, the two values in the Anisette headers. The OTP changes every 30 seconds, because it depends on the clock |
| GSA, SRP | Grand Slam Authentication is Apple's login service (`gsa.apple.com`). SRP is the password protocol it uses: `init`, then `complete` |
| Service token | What a successful login returns. `searchPartyToken` is the Find My one. It only works with the headers of the machine that made it |
| Resync (`hsc 434`) | Apple asking a machine to re-synchronise. It sends a SIM (`X-Apple-I-MD-DATA`), CoreADI's `Synchronize` turns it into an SRM, and the tool posts the SRM to `midSyncMachine` |
| PET | A password-equivalent token, valid for about 5 minutes. Obtained by re-authenticating. The keychain service wants one |
| Escrow record | A backup of a trusted device's iCloud Keychain identity. It is unlocked with **that device's screen-lock passcode** |
| BeaconStore | The CloudKit zone where Find My keeps your tags' keys, encrypted with iCloud Keychain keys |
| Master key | A tag's secret. The tag broadcasts rotating public keys derived from it, and location reports are encrypted to those keys |

## Sideloading check (read-only)

Sideloading tools (AltStore, SideStore, iloader, xtool) need two things after the login: an Xcode **app token**, and the developer-services API. `-22411` is reported at the app-token step (SideStore#1658, isideload#27). This check does both, read-only; nothing is created:

```bash
tools/aged_login.sh /tmp/macadi/NAME --dev-check --dev-save /tmp/macadi/NAME-xcode.json   # fresh login: app token + listTeams
tools/restored_run.sh /tmp/macadi/NAME --dev-from /tmp/macadi/NAME-xcode.json              # later: listTeams on the saved token, no login
```

The first needs a **fresh login** (a new 2FA push), because the app token is signed with the login's session key, which a saved login does not keep. It prints only status codes, never tokens. Seen once on one account: Apple accepts the app-token request, and `listTeams` returns the account's team. The developer API needs an **Xcode** client info (with the Anisette's akd one it answers `resultCode 1100` "session expired"). Creating certificates, App IDs or profiles, and installing apps, were not tried. The saved token file is a credential (mode 0600); its own expiry field said about a year.

## How it works

1. The tool gets the URL bag from `gsa.apple.com` and starts the machine provisioning.
2. CoreADI makes a response from Apple's challenge. The tool sends it. Apple returns the provisioning data.
3. CoreADI makes a one-time code (OTP) and a machine ID. They go into the `X-Apple-I-MD` headers. The OTP depends on the clock, so the emulated clock has to be the real one.
4. The tool does the SRP `init` and `complete` requests, then 2FA. Apple returns the tokens.
5. If Apple answers `hsc 434` with `X-Apple-I-MD-DATA`, the tool runs CoreADI's `Synchronize` on that data and posts the result to `midSyncMachine` (`tools/machoadi/resync.py`).

`MAC-ANISETTE-LOGIN.md` has the details and the error codes. `RESYNC-RUNBOOK.md` has the order of the post-cooldown experiments.

## Safety

- **Responsible use.** Only use accounts and tags that you own. The repository does not contain Apple's library; `tools/fetch_mac_coreadi.py` downloads it from Apple. Do not share the extracted library, state directories, saved logins or tag files.
- Use a **throwaway Apple Account** for experiments. Each login adds a fake Mac to the account's device list. Remove them after the tests.
- Apple rate-limits with HTTP 429, and it did so after roughly 25 requests in half an hour. Every tool here records a 429 in `/tmp/macadi/gsa-429` and refuses to talk to Apple for 45 minutes. Check with `.venv/bin/python tools/machoadi/cooldown.py`. The first 429 stops a run, and nothing is retried.
- Apple allows one provisioning for each device ID, and also for each machine. A second one returns HTTP 433 even with a fresh ID.
- The keychain route spends a device passcode guess. Type it carefully and only once.
- Never share state directories, session files, saved logins, tokens, passwords, passcodes, 2FA codes or tag keys.

## Repository map

| Path | Content |
| --- | --- |
| `auth_probe.py` | Login, 2FA, token tests, `--save-login`, `--restore-login`, `--auto-resync`, `--tags` |
| `tools/login.sh`, `aged_login.sh`, `restored_run.sh` | Make a machine and log in; log in on an existing machine; use a saved login |
| `tools/replay_aged.sh`, `replay_fresh.sh`, `flow_test.sh` | Token tests |
| `tools/fetch_tag.sh` | Fetch one tag's reports with a key you have |
| `tools/machoadi/resync.py`, `cooldown.py` | Answer Apple's resync; the shared 429 cooldown |
| `tools/machoadi/age_check.py`, `replay.py`, `fetch_reports.py` | Age probe, token replay, report fetch and decrypt |
| `tools/machoadi/login_store.py`, `tag_keys.py`, `dev_check.py` | Saved logins; tag keys from the account; the sideloading check |
| `tools/machoadi/` | Mach-O loader, Unicorn harness, Grand Slam client, mac anisette and the rest of the emulation |
| `tools/fetch_mac_coreadi.py` | Downloads CoreADI from iTunes 12.8.3 |
| `EVIDENCE.md` | What we measured, with the tests that show it |
| `MAC-ANISETTE-LOGIN.md` | Procedure and error codes |
| `RESYNC-RUNBOOK.md` | The experiments to run after a 429 cooldown, in order |

## What to report back

Share the `[restore]`, `[resync]` and replay lines, the `[tags]` lines and any error text. Remove passwords, codes, tokens, passcodes and keys first.
