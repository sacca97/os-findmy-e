# Evidence

This file lists what we measured, in the order that matters. Each result names the test that shows it. Dates are 2026-10-16. All tests used one IP address and a throwaway Apple Account.

## Summary

- A login with an emulated Mac works, 2FA included (sections 2, 3).
- For days a machine was accepted for only about a minute (sections 1, 6). **That was an artefact of our emulation**: CoreADI's clock was frozen, so the one-time code never changed (section 8). With the real clock, a fresh machine is accepted at 4 minutes, a token works at 16 minutes, a login completes at 29 minutes, and a saved login still works at 75 minutes (section 9).
- `-22421` / `hsc 434` is Apple asking for a resync, and the machine can answer (section 7).
- The tag keys can be read from the account, and a third-party tag returned location reports (section 10).
- Sections 1 and 6 are kept as they were measured. Read them with section 8.

## Background

An Apple login needs Anisette data. It proves that the request comes from a real Mac. Here, Apple's macOS CoreADI library (iTunes 12.8.3, version 4.19.0) makes the data under Unicorn emulation. For a long time Apple refused every request with `-22421`. We tried different device IDs, serials, models, builds and platform claims. None of them helped.

## 1. A new machine is accepted for about 60 seconds (with a frozen clock; see section 8)

After provisioning, Apple answers the SRP `init` request with `-20970` ("account information entered incorrectly"). This reply means that Apple accepted the machine and rejected only our made-up account. After about 60 to 75 seconds, Apple answers with `-22421` for ever.

Two fresh device IDs, provisioned together, same claim:

| Seconds since provisioning | Machine F1 (asked every 14 s) | Machine F2 (not asked) |
| --- | --- | --- |
| 0, 15, 30, 45, 59 | `-20970` (5 times) | |
| 74 | `-22421` | |
| 119 to 163 | `-22421` (4 times) | |
| about 178 | | `-22421` on the first request |

Machine F2 shows that time decides the result, not the number of requests. Four more fresh machines agree. Stores that are hours old give `-22421` on the first request.

**Result:** the earlier `-22421` results came from stores older than the window. They do not show that Apple rejects the identity.

## 2. A full login works

Setup: a fresh machine, the default claim `<MacBookPro13,2> <macOS;13.1;22C65>`, and a real throwaway account. The login starts a few seconds after provisioning.

| Step | Reply |
| --- | --- |
| SRP `init` | `ec 0` (machine and account accepted) |
| SRP `complete` | `hsc 409`, then 2FA by SMS |
| After the code | ten service tokens, including `searchPartyToken` |

With a wrong password, `complete` returns `-22406` ("Enter the correct password"). The machine is accepted in that case too.

A Find My request with an empty ID list, sent right after the login:

| Token | `acsnservice/fetch` | `findmyservice/v2/fetch` |
| --- | --- | --- |
| `searchPartyToken` | `200`, 33 bytes (empty result) | `400` (our body is not valid) |
| The other nine tokens | `401` | `401` |

**Result:** Apple accepts the emulated machine for the whole login. The `200` shows that the token and the headers are not refused. It does not show that a location report can be read.

## 3. The machine does not need to be real

The login in section 2 used a random device ID, host UUID and serial. No real Mac, no real store and no newer library were needed.

## 4. HTTP 433 means "device ID already provisioned"

`finishMachineProvisioning` returns HTTP 433 (`ec -29002`, "server error. Try again") for a device ID that was provisioned before. The reply does not depend on the source or on the time.

| Device ID | Client claim | Result |
| --- | --- | --- |
| New | Intel default | success |
| New | `Mac16,12` (Apple silicon) | success |
| One that just succeeded | Intel default | 433 |

HTTP 429 from `gsa.apple.com` (a short HTML page from the edge) was first read as a rate limit. It is Apple refusing a second request on a reused connection, not a rate limit: see `GSA-LOGIN-TRANSPORT.md`. The same applies to the escrow proxy, whose `srp_init` and `recover` share one host.

## 5. Library builds

- The CoreADI from macOS 15.8.1 runs in the same harness. It loads with two changes: the file path and the dispatcher offset (`0x17BF60`, set with `COREADI_PATH` and `COREADI_DISPATCH`). Apple answered it like version 4.19.
- On macOS 26.7.1 there is no CoreADI library. The ADI code is in a daemon (`adid`) with no exported dispatcher. The harness cannot call it.
- A current Mac stores its ADI data as one version-2 `adi.pb` file in `/private/var/db/fpsd/adi/`. Version 4.19 and version 15.8.1 write a version-1 `adi.pb` and a per-user file. We did not need the newer format.

## 6. The token is bound to its machine (the lapse measured here came from the frozen clock; see sections 8 and 9)

`tools/flow_test.sh` logs in, then sends the same `acsnservice` request every few seconds by four routes:
`live` (the logged-in account), `clean` (a new account with only the saved token), `bad` (a changed token,
the control) and `other` (a second machine, provisioned when the first is about 42 s old, with the same token).

| Run | Age of the first machine | `live` / `clean` | `bad` | `other` |
| --- | --- | --- | --- | --- |
| 1 | 8 s, 29 s | 200 / 200 | 401 | |
| 1 | 50 s, 71 s | 401 / 401 | 401 | |
| 2 | 17 s to 78 s | 200 / 200 | 401 | 401 |
| 2 | 85 s, 91 s | 401 / 401 | 401 | 401 |

**Result:**
- `bad` is `401`, so the `200` values are real.
- `live` and `clean` always agree. A saved token replays correctly.
- `other` gives `401` while the first machine still gives `200`. The token is bound to the machine that made it. A new machine cannot use it.
- The first machine stops working after 29 to 50 s in run 1 and 78 to 85 s in run 2. Requests every 6 s did not extend it. We do not know what sets the length.

A token from this method works only with its own machine, and with the frozen clock that machine lapsed after 30 to 85 seconds. **Sections 8 and 9 show that the lapse was the frozen clock.** The token is still bound to its machine.

## 7. `-22421` is Apple asking for a resync, and the machine can answer

Dumping the whole `Status` of a `-22421` refusal (earlier probes printed only `ec`, `em` and `hsc`) shows:

    hsc 434, ec -22421, X-Apple-I-MD-DATA: <base64, 36 bytes>, X-Apple-I-MD-Cmd-Target: native

`X-Apple-I-MD-DATA` is absent from accepted (`-20970`) answers and differs on every refusal. Public reverse-engineering
notes (Blackwood-4NT, unofficial) call `hsc 434` "Anisette Resync Required: headers have expired" and this field the SIM
for `ADISynchronize`. The decompiled `akd` (macOS 15) shows the reply: it posts to the URL bag's `midSyncMachine`.

| Step | Result |
| --- | --- |
| `init` on an aged machine | `hsc 434`, `ec -22421`, SIM present |
| CoreADI `Synchronize(SIM)` | `ret 0`, MID unchanged (60 bytes), SRM 121 bytes, store unchanged |
| `POST midSyncMachine` with only `{"srm": ...}` | HTTP 200, empty body (no verdict) |
| the same with `X-Apple-I-MD-M` and the plist envelope, as `akd` builds it | `ec 0` |
| `init` afterwards | `-20970`, `hsc 200`: accepted again, twice in a row |

**Limits.** One machine. After this single resync the machine was refused again within minutes.

## 8. With a frozen clock the OTP is a constant

The emulation ran CoreADI with `gettimeofday` frozen at 1700000000. `mac_anisette.py headers` in two separate processes
32 s apart gave the identical OTP. With the real clock the OTP differs in every 30-second window. A real client's OTP
changes every 30 seconds.

Also, `machine age` in `replay.py` and `--watch` was measured from the store files' mtime, which every OTP rewrites. It
therefore counted from the last OTP (after login and 2FA) and not from provisioning. The lease numbers of section 6 are
too short by the length of the login. `identity.json` now records `provisioned_at`.

## 9. With the real clock the machine, the token and a login last

Fresh machine `rt1` (new device ID), real clock, throwaway account. Ages are seconds since provisioning.

| Test | Age | Result |
| --- | --- | --- |
| credential-free `init`, no resync ever sent | 4, 46, 101, 161, 241 s | `-20970`, `hsc 200` every time |
| `acsnservice` replay with this machine's headers, no resync | 943 s | `200`, 33 bytes; bad-token control `401` |
| second login on the same machine | 1734 s | completed; no second 2FA prompt (one observation) |
| saved login restored: token check on `acsnservice`, then a password-equivalent token renewal (`init`, `complete`) | 4478 s | `200`; `ec 0` twice, no 2FA demanded |

Under the frozen clock the same kind of machine was refused from about 74 seconds in every timeline (section 1). The
only difference between the two arms is the time the library reads. The frozen clock was the cause of the lease.

**Limits.** One machine. Only the first line of the 12-request replay was recorded. Not shown: any age beyond about
75 minutes, a token that survives hours or days, a real location report, and a longer test than about 75 minutes.

## 10. The tag keys can be read from the account

`tag_keys.py`, saved login, real clock, one account. The CloudKit device identifier is the machine's host UUID.

| Step | Result |
| --- | --- |
| list escrow records (no passcode) | 1 recoverable record: the account's iPhone |
| recover with that iPhone's screen-lock passcode (one try) | succeeded |
| keychain keys, then BeaconStore decrypt | 2 accessories: the iPhone, and a third-party "Smart Tracker" paired through Find My |

A third-party tag paired through Find My is an ordinary BeaconStore beacon with a private key. Nothing was written to
the account (the keychain `join` is never called).

Fetching with the saved tags (no passcode): the iPhone returned 0 reports, the Smart Tracker returned 8, the newest
within the previous half hour, accuracy 52 to 102 m. So the library's AirTag key derivation works for this tracker.
Coordinates are not recorded here.

## 11. The developer API accepts the emulated machine

`auth_probe.py --dev-check`, fresh login with 2FA, real clock, made-up device values; then `--dev-from` with the saved token and no new login.

| Step | Result |
| --- | --- |
| `apptokens` for `com.apple.gs.xcode.auth` | `ec 0`, `hsc 200` |
| decrypt the returned token (AES-GCM, key `sk`) | works; the plaintext is a bare `<dict>` plist |
| `listTeams`, client info as the Anisette gives it (`com.apple.akd`) | HTTP 200, `resultCode 1100` "Your session has expired" |
| `listTeams`, client info presenting Xcode | HTTP 200, `resultCode 0`, 1 team |

`-22411` is reported at the app-token step by other sideloading users (SideStore#1658, isideload#27); the emulated machine passed it. The `1100`
was not an expired session: the developer API answers it when the client info does not look like Xcode, the mirror image of the login endpoint,
which drops Xcode client info and wants akd. The token's own expiry field said about a year. One account, one run. Not tried: creating App IDs,
certificates or profiles, registering a device, installing an app.

## Open questions

- **How long does it last now?** Beyond about 30 minutes, with the real clock: hours, days? A single replay an hour later tells.
- **Does a saved login keep working?** `tools/restored_run.sh` checks the token with one request and says when to log in again.
- **Do the identity and claim variants matter inside the window?** We measured most of them outside it, so those results do not apply.
- **What happens on the account side?** Each login adds a fake Mac to the device list. We did not count them.

