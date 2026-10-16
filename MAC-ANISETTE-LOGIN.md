# Mac Anisette login on Linux

This document shows how to log in to an Apple Account on Linux. The login uses Anisette data from the Mac CoreADI library. The library runs under Unicorn emulation.

## Result

The login completes, including two-factor authentication. The account then holds service tokens, for example `searchPartyToken`.

## Rules

1. Apple accepts a new machine for about 60 seconds after provisioning. After that time, Apple refuses the machine with `-22421`.
2. Provision and log in in one command. Do not wait between the two steps.
3. The machine does not need to be real. A random device ID, host UUID and serial are sufficient.
4. Use the default client info `<MacBookPro13,2> <macOS;13.1;22C65>`. A different model or macOS version has no effect.
5. Apple allows one provisioning for each device ID. A second provisioning of the same ID returns HTTP 433. Use a new state directory for each login.

## Flow

1. The tool gets the URL bag from `gsa.apple.com`.
2. The tool sends `startMachineProvisioning`. Apple returns a SPIM.
3. CoreADI makes a CPIM from the SPIM. It uses the host UUID.
4. The tool sends `finishMachineProvisioning` with the CPIM. Apple returns a PTM and a TK.
5. CoreADI completes the provisioning and writes the store to the state directory.
6. CoreADI makes an OTP and a machine ID (MID). The tool sends them in the `X-Apple-I-MD` headers.
7. The tool sends the SRP `init` request. Apple returns `ec 0`.
8. The tool sends the SRP `complete` request. Apple returns `hsc 409` when two-factor authentication is necessary.
9. The user enters a code from a trusted device or from SMS.
10. Apple returns the service tokens.

## Procedure

Run both commands in one line. The login must start within 60 seconds of the provisioning.

```
S=/tmp/macadi/login; rm -rf $S $S-auth
.venv/bin/python tools/machoadi/mac_anisette.py provision --state $S && \
.venv/bin/python auth_probe.py --macadi $S --state-dir $S-auth
```

The 2FA code comes from a trusted device by default. Add `--2fa sms` to `tools/login.sh` (or `--sms` to `auth_probe.py`) to get the code by SMS. The tool asks for the Apple ID and the password. Do not put them in a file or in the command line.

## Time budget for 2FA

The library signs in again after you enter the 2FA code: a second `init` and a second `complete`. The second `complete` only works while the machine is young, about 40 seconds after provisioning. If you are slower, Apple answers `-22406` ("Enter the correct password"), even when the password is correct.

- Use `--2fa sms` when you can. The code arrives in seconds.
- With a device code, keep the device unlocked and type the code at once.
- Each request in the log shows `machine_age_s`. A `complete` with an age above about 40 is the likely cause of a false `-22406`.

## Error codes

| Code | Meaning |
| --- | --- |
| HTTP 433 (`-29002`) | The device ID is already provisioned. Use a new ID. |
| `-22421` | Apple refuses the machine. The provisioning is older than about 60 seconds. |
| `-20970` | Apple accepts the machine. The account name is not valid. |
| HTTP 429 | Apple limits the number of requests. Wait at least one hour. |
| `-22406` | Apple accepts the machine. The password is not correct. |

## Not known

- Whether anything makes the machine's registration last longer. A token works only with its own machine, for about 30 to 85 seconds.
- Whether a real location request returns data.
- How many devices the account shows after each login. Remove the fake Macs from the device list.

Use `tools/flow_test.sh` to test the token. See `README.md` for the test and `EVIDENCE.md` for the evidence.
