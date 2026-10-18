# Live validation — manual runbook

Every step below talks to Apple; none is run by the test suite. Read the safety rails first, run steps one at
a time, and stop at the first refusal. The Python tools under `tools/machoadi/` and `tools/*.sh` are the
reference used for the results in `EVIDENCE.md`; this guide checks the Rust implementation against them.

`findmy` is already on `PATH` and the CoreADI is staged, so every command below is just `findmy <command>`:

    # already done; re-run only if you move it:
    cargo install --path native/findmy-cli
    cp native/../app/prebuilt/assets/CoreADI-4.19-x86_64 ~/.findmy/CoreADI

State lives in `~/.findmy` (override with `--state-dir`/`$FINDMY_STATE`); `machine.json`, `session.json`,
`pcs.json`, `tags.json` and the 429 marker all go there, written 0600. The CoreADI is found at
`~/.findmy/CoreADI` (or `--images FILE`/`$FINDMY_COREADI`; use a macOS 15.8.1 image only when testing that build).

## What you need

* your **Apple ID** and password (asked for on stdin, hidden; never written).
* for the report step, the **base64 private key of one of your own tags** (`FINDMY_KEY`).
* a machine you can afford to provision: Apple allows **one provisioning per device id**; a second returns
  HTTP 433. Provisioning also spends from the shared per-IP budget.

## Safety rails (in the tool)

* Every command that sends anything requires `--yes`; without it the tool prints what it would do and stops.
* Every command that sends anything also has `--dry-run`, which prints the plan (the URLs and the number of
  requests) and sends nothing; it does not require `--yes` and does not need the machine/session. Use it to
  check that a step is what you think before running it for real. `findmy <cmd> --dry-run`.
* A shared **429 cooldown** is recorded next to the state (`<state-dir>/gsa-429`); nothing is sent while it is
  active (45 min). A 429 from any step records it. `--ignore-cooldown` overrides it; do not use it.
* Secrets are redacted: `X-Apple-I-MD*` prints as a length and a prefix, never the value; no password,
  passcode, token or key is ever printed or written except `pcs.json` / the tag key you supply.
* `provision` uses saved credentials when it finds them and only overwrites with an explicit `--override`.
* `keychain-recover` sends **one** passcode guess and never retries.

## How many requests, and what stops them

Every loop is bounded; there is no retry-on-failure except the two below. `--dry-run` prints these plans.

| Step | Requests (typical) | Bound |
| --- | --- | --- |
| `root-ca` | 1 | one GET |
| `machine-headers` | 0 | offline |
| `machine-probe` | 1 | one `init` |
| `provision` | 3 | URL bag + start + finish |
| `login` | 3 (9 with 2FA) | each SRP exchange is init+complete; the delegate is one |
| `reports` per accessory | 1 (6 if nothing found) | `--max-requests N`, default 6 |
| `reports` total | 1 | `--limit N`, default 3 accessories |
| `keychain-list` | 5 | container + PET (2) + viable + escrow listing |
| `keychain-recover` | ~13 | PET (2) + listing (2) + `srp_init` + `recover` + `fetchChanges` + `fetchRecoverableTLKShares` + the two view fetches |
| `beacons` | 3–4 | container + zone retrieve + BeaconStore pages |

A full read-only flow (root check, one login, one report, keychain list+recover, beacons) is about **25–30
requests**, plus 3 if you provision and 6 if 2FA is needed. A `429` stops the run and records the cooldown.
The only automatic repeats are: Apple answering an empty 200 to a report fetch (up to five retries, as the
Python does), and a `hsc 434` answered with one resync and one repeat of the same request.

A stale accessory alignment can make one rolling-key walk cover more than the 7-day window; the CLI caps
that at `--max-requests` per accessory and stops after `--limit` accessories, so one command can never turn
into an unbounded walk.

## Steps

### 0. Offline sanity (no Apple)
    findmy machine-headers --second
One Anisette header set, then another 31 s later. It must say `OK: X-Apple-I-MD changed`. If it does not,
the clock is frozen (see `EVIDENCE.md` §8/§9) — stop; that would reproduce the ~60 s lease.

### 1. TLS trust
    findmy root-ca --yes
A GET to `https://gsa.apple.com/`. Any HTTP status is fine; what matters is that the TLS handshake
succeeded with the bundled, hash-checked Apple 2006 root and only the bundled web roots. This settles the
*library*; the Android app's device check (`app/`) is separate.

### 2. Machine lease — the clock question / resync path
    findmy machine-probe --yes
A credential-free SRP `init` with a synthetic account (the `tools/machoadi/gsa_init.py` probe). **Only a
`hsc 434`/`ec -22421` is a machine verdict** (the lease lapsed; the login answers it with a resync
automatically). Every other `ec` is Apple's verdict on the *synthetic account*, which means the machine's
Anisette was accepted and processed:
* `ec -20970` → the machine is accepted and the account is unknown: **good**.
* `ec -20209` → the machine is accepted and Apple calls the synthetic **account** locked (observed
  2026-10-18, age 61 s); an account verdict, not a machine one. Record it — it is new.
* `ec 0` / `-22406` → accepted; an account verdict.
* `hsc 434` / `ec -22421` → the lease has lapsed. To see the resync path alone, use the Python hold test
  (`tools/machoadi/resync.py --state STATE --dry-run` first, then `--rounds 1`).
* anything else → record it verbatim with Apple's `em`.

Run it again after a few minutes; the machine should still be accepted (with the real clock). The Python
cross-check is `tools/machoadi/age_check.py --state STATE --clock real --existing --ages 60,300`.

### 3. Provisioning (only if you have no machine, or are testing a different CoreADI build)
    findmy provision --yes
Writes `./state/machine.json`. If testing the macOS 15.8.1 image, repeat step 2 and step 4 with that machine.
Record the routing value and whether `probe` and `login` accept it.

### 4. Login (SRP + 2FA)
    findmy login --yes
Asks for the Apple ID and password (hidden), lists the second-factor methods, and asks for the code. It
answers a `hsc 434` with a resync and repeats the request once. **For the trusted-device method it first
asks Apple to push the prompt** (`GET /auth/verify/trusteddevice`); the prompt does not arrive on its own.
A failed push request is non-fatal (it prints a warning and still asks for a code); `--no-push` skips it.
Record:
* whether `sp` was `s2k` or `s2k_fo` — the tool does not print it; watch for a failure instead;
* the second-factor method and whether the Xcode-flavoured 2FA request was accepted;
* any `-22406` responses, which can help identify an SRP compatibility issue.
On success it writes `state/session.json` (dsid + service tokens, no password, no PET). Run the login a
second time on the same machine to confirm it is accepted again.

Python cross-check: `tools/aged_login.sh STATE` (existing machine, auto-resync).

### 5. Report fetch

Simplest first (one tag, one request), as the Python's `fetch_reports.py`:
    read -rs FINDMY_KEY; export FINDMY_KEY        # base64 private key of ONE of your own tags
    findmy reports --yes
`--tag-key BASE64` does the same without the environment.

Or the full path, with the accessories `beacons` writes:
    findmy reports --yes --keys ~/.findmy/tags.json --limit 1

`tags.json` is a `FindMyAccessory` JSON array (what `tag_keys.py --tags-save` or step 9 writes). Record the
HTTP status, `acsnLocations.statusCode`, whether the AuthKit UA was accepted (try
`--report-user-agent "Python/3.14 aiohttp/3.14.5"` if it is refused), the header set (no `X-MMe-Client-Info`),
any 89-byte report, and 429/`Retry-After`/empty-200/401.

### 6. Token lifetime
Re-run step 5 with the same `state/session.json` after minutes and then hours, without logging in again.
The Python reference did this with `tools/replay_aged.sh STATE` (same machine) and
`tools/replay_fresh.sh SESSION` (a machine provisioned seconds ago): a token that works with its own
machine and is refused by a fresh one is the expected binding.

### 7. Keychain listing — Tier 2, no passcode
    findmy keychain-list --yes
Lists the escrow records Apple holds (`recovery_options`). This creates nothing and needs no passcode.
It asks for the Apple ID password once, only to renew the PET (the escrow proxy authenticates with the
short-lived PET; a restored session has none). Record the record count, the device descriptions and the
viable/not-viable split. Python cross-check: `tools/machoadi/tag_keys.py --tags-list`.

### 8. Keychain recovery — one passcode guess (Tier 2)
    findmy keychain-recover --yes
Prompts for the record index and then the **screen-lock passcode of that device** (hidden). It sends
**one** guess through the SRP exchange and never retries; a wrong guess counts against Apple's limit on the
record. On success it writes `state/pcs.json` (the elliptic-curve keychain keys, 0600). Record the number of
keys and whether the exchange refused a correct passcode (Apple's escrow sometimes returns `-6015`; the
Python retried the identical call successfully). Python cross-check: `tools/machoadi/tag_keys.py`.

### 9. BeaconStore — Tier 2
    findmy beacons --yes
Uses `state/pcs.json` to unwrap the BeaconStore zone, fetch its records, decrypt them, and print the
accessories (name, model, serial; the master key is redacted). It also writes `state/tags.json` (0600) in the
`FindMyAccessory` shape, which `reports --keys` reads. Record: the record counts by type, how many decrypted,
what was skipped and why, and whether every expected tag appears. This is the read-only end of the whole
flow.

## Recording results

For each step, note the date, the machine age, the CoreADI build, the exact command, the HTTP status and
Apple's `status`/`ec`/`hsc`/`em`, and anything unexpected. Record the results in a separate note; the
existing `EVIDENCE.md` describes the Python reference runs. A step that produces a refusal
is a result, not a failure; what must never happen is a retry loop or a second provisioning on the same
device id.

## Stop conditions

Stop immediately, record, and do not retry, on:
* HTTP **429** (the tool records the cooldown and stops; do not use `--ignore-cooldown`);
* HTTP **433** during provisioning (this device id is already provisioned — use a new one, do not retry);
* a **`hsc 434`** that the automatic resync does not clear;
* any **passcode failure** in step 8 (one guess only, by design);
* a machine that stops being accepted where the frozen clock is not the cause — this is the signal to go
  back to the Python `tools/machoadi/resync.py` hold test before changing any code.

## Android

Android TLS validation is separate from this CLI and must be checked from the app on a device.
