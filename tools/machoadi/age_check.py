#!/usr/bin/env python3
"""Does the lease depend on the emulated clock?  Credential-free, never resyncs.

The emulation has always run CoreADI with `gettimeofday` frozen at 1700000000, which makes the
OTP a constant (the same bytes 32 s apart, in separate processes). A real client's OTP changes
every 30 s. If Apple's acceptance depends on the OTP's time being near its own, a frozen clock is
exactly a ~60 s lease: accepted while that time is close, `hsc 434 / -22421` after.

This provisions a FRESH machine (new device id, new state directory) and sends one synthetic-account
`init` at each age, with the clock you choose:

    .venv/bin/python tools/machoadi/age_check.py --state /tmp/macadi/rt1 --clock real
    .venv/bin/python tools/machoadi/age_check.py --state /tmp/macadi/rt1 --dry-run

Reading it: `-20970 / 200` = accepted, `-22421 / 434` = refused (lease over).
  real clock: -20970 at ages 100, 160, 240 .... the frozen clock WAS the lease; the token should now last
  real clock: -22421 from ~60-75 s on ......... the clock is not the cause (the frozen timelines of
                                                 EVIDENCE.md section 1 are reproduced); go on to the resync hold test
It never answers a 434 (no Synchronize, no syncMachine), so the age is pure.
Requests: 3 for provisioning, 1 URL bag, 1 per age. Refuses to run during a recorded 429 cooldown and
stops at the first 429.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", required=True, type=Path, help="NEW state directory (must not exist)")
    ap.add_argument("--clock", choices=["real", "frozen"], default="real")
    ap.add_argument("--ages", default="3,45,100,160,240", help="seconds since provisioning, comma separated")
    ap.add_argument("--existing", action="store_true",
                    help="probe an already provisioned state at these ages (seconds since ITS provisioning) "
                    "instead of provisioning; ages already past are sent at once, so pass future ones")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ignore-cooldown", action="store_true")
    args = ap.parse_args()
    ages = [int(x) for x in args.ages.split(",")]

    import cooldown  # noqa: PLC0415

    print(f"plan: {'probe existing' if args.existing else 'provision'} {args.state} with the {args.clock} clock, "
          f"init at ages {ages} s; {(1 if args.existing else 4) + len(ages)} requests; cooldown {cooldown.remaining() / 60:.0f} min left", flush=True)
    if args.dry_run:
        print("dry run: nothing sent")
        return 0
    if args.existing and not (args.state / "identity.json").exists():
        raise SystemExit(f"{args.state} is not a provisioned state")
    if not args.existing and args.state.exists():
        raise SystemExit(f"{args.state} exists: a state is provisioned once (HTTP 433), use a new directory")
    cooldown.guard(args.ignore_cooldown)
    if args.clock == "real":
        os.environ.pop("ADI_FROZEN_TIME", None)
    else:
        os.environ["ADI_FROZEN_TIME"] = "1"

    from mac_anisette import MacAnisette  # noqa: PLC0415
    from resync import Resyncer  # noqa: PLC0415

    try:
        if not args.existing:
            MacAnisette(args.state).provision()
        resyncer = Resyncer(args.state, max_requests=4 + len(ages))
        if args.existing:
            print(f"machine age now {resyncer.age()} s", flush=True)
        for age in ages:
            time.sleep(max(0.0, resyncer.born + age - time.time()))
            verdict = asyncio.run(resyncer.probe())
            print(json.dumps({"clock": args.clock, "age_s": resyncer.age(), "at": time.strftime("%H:%M:%S"),
                              "ec": verdict.get("ec"), "hsc": verdict.get("hsc"),
                              "sim": bool(verdict.get("sim_b64")), "error": verdict.get("error")}), flush=True)
    except cooldown.Throttled as error:
        print(json.dumps({"stage": "STOP", "reason": "HTTP 429", "detail": str(error)[:200]}), flush=True)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
