# Mac Anisette login on Linux

This document shows how to log in to an Apple Account on Linux. The login uses Anisette data from the Mac CoreADI library. The library runs under Unicorn emulation.

## Result

The login completes, including two-factor authentication. The account then holds service tokens, for example `searchPartyToken`. With the real clock (the default now) the machine stays accepted for at least 4 minutes, a token worked 16 minutes after provisioning, and a login on a 29-minute-old machine completed.

## Rules

1. **The emulated clock must be the real one.** CoreADI's OTP depends on the time. With a frozen clock the OTP never changes, and Apple accepts the machine for only about 60 seconds. The real clock is the default. `ADI_FROZEN_TIME=1` restores the frozen clock, which is only useful to reproduce the old behaviour.
2. The machine does not need to be real. A random device ID, host UUID and serial are sufficient.
3. Use the default client info `<MacBookPro13,2> <macOS;13.1;22C65>`. A different model or macOS version has no effect.
4. Apple allows one provisioning for each device ID, and also for each machine. A second provisioning returns HTTP 433, even with a new ID. Use a new state directory for each new machine, and reuse a machine for later logins.
5. A token works only with the headers of the machine that made it. A different machine cannot use it.
6. If Apple answers `hsc 434` (`-22421`) with `X-Apple-I-MD-DATA`, the machine has to resync. `auth_probe.py --auto-resync` and `tools/machoadi/resync.py` do it.
7. Apple rate-limits with HTTP 429. A 429 is recorded and stops every tool for 45 minutes.

## Flow

1. The tool gets the URL bag from `gsa.apple.com`.
2. The tool sends `startMachineProvisioning`. Apple returns a SPIM.
3. CoreADI makes a CPIM from the SPIM. It uses the host UUID.
4. The tool sends `finishMachineProvisioning` with the CPIM. Apple returns a PTM and a TK.
5. CoreADI completes the provisioning and writes the store to the state directory. The tool records `provisioned_at` in `identity.json`.
6. CoreADI makes an OTP and a machine ID (MID). The tool sends them in the `X-Apple-I-MD` headers. A new OTP is made for every 30-second window.
7. The tool sends the SRP `init` request. Apple returns `ec 0`.
8. The tool sends the SRP `complete` request. Apple returns `hsc 409` when two-factor authentication is necessary.
9. The user enters a code from a trusted device or from SMS.
10. Apple returns the service tokens.

### Resync

When Apple wants the machine to resync, it answers a request with `hsc 434`, `ec -22421` and `Status -> X-Apple-I-MD-DATA` (a server message, called the SIM).

1. CoreADI's `Synchronize` turns the SIM into an SRM and returns the MID.
2. The tool posts `{"srm": <b64>, "X-Apple-I-MD-M": <b64 MID>, "X-Apple-I-MD-RINFO": <int>}` to the URL bag's `midSyncMachine`, in the usual `{"Header": {}, "Request": ...}` plist. The shape comes from the decompiled `akd`.
3. Apple answers `ec 0`, and the next `init` is accepted again.

## Procedure

New machine and login in one command. The tool asks for the Apple ID and the password first, so typing does not use up the time:

```
tools/login.sh NAME [--2fa device|sms]
```

Login on a machine that already exists, saving the login for later:

```
tools/aged_login.sh /tmp/macadi/NAME [--2fa device|sms]
```

Use the saved login (no password, no 2FA):

```
tools/restored_run.sh /tmp/macadi/NAME
```

The trusted-device code is the default, and the push prompt is requested for you (`--no-request-push` turns that off). The tools ask for the Apple ID and the password. Do not put them in a file or in the command line. The saved login file is the one exception, and it is opt-out: it holds the tokens and the password in clear text, mode 0600. Delete it when done.

## Time budget for 2FA

With the real clock, the machine no longer lapses after about a minute, so the 2FA code is not a race any more. `--preflight` adds a credential-free check before the login and again before the code is submitted. It costs Apple requests, and it is off by default. A `hsc 434` during the login is still answered.

With the old frozen clock, the second `complete` after the code only worked while the machine was young, and a late one was answered `-22406` ("Enter the correct password") even with a correct password. A `-22406` at a high machine age is therefore not proof of a wrong password.

## Error codes

| Code | Meaning |
| --- | --- |
| HTTP 433 (`-29002`) | The device ID or the machine is already provisioned. Use a new state directory. |
| `-22421` / `hsc 434` | Apple wants a resync. Answer it with `Synchronize` and `midSyncMachine`. Seen from a frozen clock after about 60 s. |
| `-20970` | Apple accepts the machine. The account name is not valid. |
| HTTP 429 | Apple limits the number of requests. The tools record it and wait 45 minutes. |
| `-22406` | Apple accepts the machine. The password is not correct, or the machine is old with a frozen clock. |

## Not known

- How long a machine and a token last beyond about 30 minutes, with the real clock.
- Whether the token and the machine survive hours or days without any resync.
- Whether a real location request returns data.
- Whether the keychain route (`tag_keys.py`) works through the emulated machine. The first try stopped at an HTTP 429.
- How many devices the account shows after each login. Remove the fake Macs from the device list.

Use `tools/replay_aged.sh` to test the token. See `README.md` for the tests and `EVIDENCE.md` for the evidence.
