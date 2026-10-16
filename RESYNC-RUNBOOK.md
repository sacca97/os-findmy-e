# Runbook: make the token last (run after the 429 cooldown)

Everything below is prepared and tested offline (`.venv/bin/python -m unittest test_resync test_auth_probe`).
Nothing here provisions a machine except Step 0, and nothing logs in except Step 2.

## Rails that are always on
- **Shared cooldown.** Any 429 is recorded in `/tmp/macadi/gsa-429`; every tool refuses to send anything
  for 45 minutes after it and says so. Check with `.venv/bin/python tools/machoadi/cooldown.py`. The marker
  is seeded with the 429 of today's 12:53 (local); it ends at 13:38.
- **First 429 stops the run.** No retries. Do not restart anything in the same hour.
- **Request caps** (`--max-requests`) and a `--dry-run` that prints the plan and sends nothing.
- **Ages are seconds since provisioning** (`identity.json: provisioned_at`), not the store's mtime. Every OTP
  rewrites the store, so `replay.py` and `--watch` had been counting from the last OTP (after login and 2FA):
  the lease numbers of EVIDENCE.md section 6 are *under*-estimates by the login time.

## Step 0 (new, cheapest, most informative): is the lease just a frozen clock?
The emulation runs CoreADI with `gettimeofday` frozen at 1700000000, so the OTP is a constant (verified: same
bytes 32 s apart in separate processes; with a real clock it changes every 30 s). A fixed OTP time that
Apple accepts only near its own clock would look exactly like a ~60 s lease and a "headers have expired" 434.
Not proven; this is the test. Credential-free, 9 requests, one new machine:

    .venv/bin/python tools/machoadi/age_check.py --state /tmp/macadi/rt1 --dry-run
    .venv/bin/python tools/machoadi/age_check.py --state /tmp/macadi/rt1 --clock real

| answers at ages 3, 45, 100, 160, 240 s | meaning |
| --- | --- |
| `-20970/200` at every age | the frozen clock was the lease. The real clock is now the default everywhere |
| `-20970` then `-22421/434` from ~60-75 s | the clock is not the cause; continue with Step 1 |

`rt1` is then also a young machine for Step 2 (if Step 0 succeeded it is still accepted afterwards).

## Step 1: hold test with resync (no login, no 2FA)
Uses a machine that is already aged. A fresh OTP is minted for every `init`, so a refusal cannot be a stale OTP.

    .venv/bin/python tools/machoadi/resync.py --state /tmp/macadi/age1 --rounds 10 --delay 45 --dry-run
    .venv/bin/python tools/machoadi/resync.py --state /tmp/macadi/age1 --rounds 10 --delay 45 | tee /tmp/macadi/hold-test.log

At most 3 requests per round (31 for ten rounds, ~4 per minute is the worst case; a round only costs 1 when the
machine is still accepted). Per round it prints `init-before`, and on 434 `synchronize`, `syncMachine`,
`init-after`, plus `lease: seconds_since_last_sync`, the time from a sync to the next 434.
- `init-before` stays `-20970` for several rounds: the machine is held open between syncs.
- 434 every round with `lease` ~ the poll gap: each sync buys about that long; a client has to answer
  continuously (viable, and what akd does).
- `syncMachine` `ec != 0` partway: the renewal ends there (record the `ec`/`em`).
- `STOP` line with `HTTP 429`: stop for the hour.
(Use `--delay 240` only if you want sparse sampling; at 240 s every round is a 434 by design.)

## Step 2: login on an aged machine, with resync inside the login
Only when you are watching: it spends a real login and a 2FA code. Prefer `--2fa sms` (the code arrives in seconds).
The real clock is the default.

    tools/aged_login.sh /tmp/macadi/age1 --2fa sms

What it does, in this order: preflight resync (aborts *before* the password is used if Apple still refuses the
machine) -> login (any 434 is answered and the request repeated) -> after you type the code, renew again, then
submit (a late second `complete` is answered `-22406` and not 434, which is why this renewal is explicit) -> saves
`/tmp/macadi/age1-session.json` (0600: dsid + searchPartyToken). If the login fails with `-22406` at a machine
age well past the lease, do not retry blindly: that is the signature of a lapsed machine, not a wrong password.

## Step 3: does the token keep working? (the question that matters)
Replays with the SAME machine's headers, as machine A, never a fresh machine (EVIDENCE.md section 6: a token only works
with its own machine's headers). Run a minute or two after Step 2:

    tools/replay_aged.sh /tmp/macadi/age1 12 30 45   # fetch every 30 s, resync every 45 s
    tools/replay_aged.sh /tmp/macadi/age1 8 60 0     # control: no resync, the bare lease

Each fetch prints machine age, the status (200 expected) and the bad-token control (401 expected). Any non-200
prints the response's Apple headers and body, and `carries_SIM=True/False`: if the fetch endpoint itself returns an
`X-Apple-I-MD-DATA` it is answered and the fetch retried once.
- 200 throughout with resync, 401 after the lease without it: **the token is renewable**. Record it.
- 401 even with resync: the endpoint wants something `init` does not show; the dumped 401 is the new lead.

## Record
Whatever happens, write the table into `EVIDENCE.md` as a new section, with
ages measured from provisioning and the clock used. Only then touch `README.md` / `MAC-ANISETTE-LOGIN.md`.

## Step 4: get the tag keys from the account, then fetch the tag (route C, read-only)
Apple stores the tag keys end-to-end encrypted in CloudKit (`BeaconStore`), protected by iCloud Keychain keys.
`tools/machoadi/tag_keys.py` (run inside a login with `--tags`) reads them with the library's *read-only* path:
list escrow records -> you choose a device and type ITS screen-lock passcode -> recover the escrowed peer -> read the
keychain keys -> decrypt the BeaconStore records into accessories -> fetch each one's locations.
It never calls `join()` (the library's one irreversible call; its own docstring says reading does not need it).

The real clock is now the default (`ADI_FROZEN_TIME=1` brings the old frozen one back). A login is SAVED by
default (`STATE-login.json`, mode 0600, holds the service tokens and the password: a credential, delete it when done),
so only the first run logs in; later runs use `tools/restored_run.sh` with no login and no 2FA.

    # 4a. log in once (push prompt is requested by default). No passcode, no risk: does CloudKit accept our
    #     machine, and what can the account be recovered from?
    tools/aged_login.sh /tmp/macadi/rt1 --tags --tags-list

    # 4b. the real thing, on the saved login. Have the passcode of the chosen device ready; asked ONCE, never retried.
    tools/restored_run.sh /tmp/macadi/rt1 --tags --tags-save /tmp/macadi/rt1-tags.json

In 4b the script lists the records, picks the only one (or asks which), shows the device, and asks for the passcode. A wrong passcode counts against Apple's guess limit on that device's escrow record, so on the first failure it
stops. `--tags-save` keeps the decrypted accessories (their master keys are secrets, file mode 0600) so later fetches
need no passcode and no keychain at all.

What 4a can show: an error on `open` or `recovery_options` means CloudKit/escrow rejects our machine's headers (then
paste me the message); `0 recoverable record(s)` means no device on the account can be recovered from, and route C is
closed (route A, a Mac export, is then the way).
