# Evidence

This file lists what we measured, in the order that matters. Each result names the test that shows it. Dates are 2026-10-16. All tests used one IP address and a throwaway Apple Account.

## Background

An Apple login needs Anisette data. It proves that the request comes from a real Mac. Here, Apple's macOS CoreADI library (iTunes 12.8.3, version 4.19.0) makes the data under Unicorn emulation. For a long time Apple refused every request with `-22421`. We tried different device IDs, serials, models, builds and platform claims. None of them helped.

## 1. A new machine is accepted for about 60 seconds

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

HTTP 429 is the real rate limit. It comes from the edge as an HTML page, and it appeared after many logins in one day.

## 5. Library builds

- The CoreADI from macOS 15.8.1 runs in the same harness. It loads with two changes: the file path and the dispatcher offset (`0x17BF60`, set with `COREADI_PATH` and `COREADI_DISPATCH`). Apple answered it like version 4.19.
- On macOS 26.7.1 there is no CoreADI library. The ADI code is in a daemon (`adid`) with no exported dispatcher. The harness cannot call it.
- A current Mac stores its ADI data as one version-2 `adi.pb` file in `/private/var/db/fpsd/adi/`. Version 4.19 and version 15.8.1 write a version-1 `adi.pb` and a per-user file. We did not need the newer format.

## 6. The token is bound to its machine, and the machine lapses within about a minute

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

A token from this method works only with its own machine, for about 30 to 85 seconds. Every use needs a new machine, a new login and a new 2FA. This is not a persistent session.

## Open questions

- **Why does the machine lapse?** Does anything renew it or make it permanent? A real client keeps its registration, so the emulation may lack a step or attested data.
- **Do other lineages last longer?** The Android library is the obvious comparison. A credential-free `init` probe at growing ages shows it without a login.
- **Does a real location report come back?** This needs the private key of a tag you own. Use `FINDMY_KEY` with `tools/flow_test.sh`.
- **Do the identity and claim variants matter inside the window?** We measured most of them outside it, so those results do not apply.
- **What happens on the account side?** Each login adds a fake Mac to the device list. We did not count them.
