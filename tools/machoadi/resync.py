#!/usr/bin/env python3
"""Answer Apple's anisette resync (hsc 434) and, optionally, hold a machine open over many rounds.

`init` is answered `hsc 434 / ec -22421` once a machine's lease has run out, with a Server
Intermediate Message in `Response -> Status -> X-Apple-I-MD-DATA` (EVIDENCE.md section 7). A real
client turns it into an SRM with CoreADI's `ADISynchronize` and POSTs it to the URL bag's
`midSyncMachine` (shape recovered from akd, EVIDENCE.md section 7):

    {"Header": {}, "Request": {"srm": <b64>, "X-Apple-I-MD-M": <b64 MID>, "X-Apple-I-MD-RINFO": <int>}}

This module is both the library the other tools use (`Resyncer`) and the hold test:

    .venv/bin/python tools/machoadi/resync.py --state S --dry-run             # plan only, sends nothing
    .venv/bin/python tools/machoadi/resync.py --state S --rounds 10 --delay 45

One round is a credential-free `init` with a synthetic Apple ID and a *freshly minted OTP*
(the earlier version minted one OTP per process, and an OTP is only good for a 30 s window, so
later rounds could be refused for that reason and not for the lease). If the answer is 434 it
synchronises, posts, and asks `init` again. At most 3 requests per round.

Safety rails, all on by default:
  * the shared cooldown (`cooldown.py`): refuses to start within 45 min of any recorded 429;
  * the first 429 stops the run and records the time -- nothing is retried;
  * `--max-requests` (default 40) caps the whole run.
Every line carries `age_s`, the seconds since the machine was *provisioned* (not the store's mtime).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cooldown  # noqa: E402
from cooldown import Throttled  # noqa: E402
from findmy import AsyncAppleAccount  # noqa: E402
from gsa import GSA, Device, GSAError  # noqa: E402
from gsa_init import CLIENT_IDENTITY, CLIENT_SERIAL, CONTEXT, StaticAnisetteProvider  # noqa: E402
from mac_anisette import DS_ID, MacAnisette, provisioned_at  # noqa: E402

REFUSED = (-22421, 434)  # (ec, hsc): "Anisette Resync Required: headers have expired"
ACCEPTED_EC = {-20970, -22406, 0}  # machine accepted (synthetic account unknown / password wrong / ok)


def sim_from_response(response) -> str | None:  # noqa: ANN001
    """The SIM, wherever Apple put it: the plist body's Status, or an HTTP header."""
    import plistlib  # noqa: PLC0415

    try:
        plist = plistlib.loads(response.content)
        body = plist.get("Response") if isinstance(plist, dict) else None
        if isinstance(body, dict):
            status = body.get("Status") or {}
            if isinstance(status, dict) and status.get("X-Apple-I-MD-DATA"):
                return str(status["X-Apple-I-MD-DATA"])
    except Exception:  # noqa: BLE001 - a non-plist body carries nothing of ours
        pass
    for name, value in dict(getattr(response, "headers", {}) or {}).items():
        if name.lower() == "x-apple-i-md-data":
            return str(value)
    return None


class Resyncer:
    """Talks to MidService/Grand Slam as one provisioned machine, and keeps it answered."""

    def __init__(
        self,
        state: Path | str,
        *,
        max_requests: int = 40,
        log: Callable[[dict], None] | None = None,
        on_synced: Callable[[], None] | None = None,
    ) -> None:
        self.state = Path(state)
        self.identity = json.loads((self.state / "identity.json").read_text())
        self.born = provisioned_at(self.state)
        self.max_requests = max_requests
        self.requests = 0
        self.on_synced = on_synced
        self._log = log or (lambda row: print(json.dumps(row), flush=True))
        self.machine = MacAnisette(self.state)
        CONTEXT["host_uuid"] = self.machine.identity["host_uuid"]
        self.client_info = self.machine.identity["client_info"]
        self.gsa = GSA(Device(self.identity["device_id"], self.client_info,
                              self.identity["local_user_uuid"], self.identity.get("serial")))
        self._urlbag_loaded = False  # loaded on first use: it is an Apple request that most runs never need
        self.preflight = False
        self.last_sync: float | None = None

    # -- bookkeeping -------------------------------------------------------
    def age(self) -> int:
        return round(time.time() - self.born)

    def log(self, stage: str, **fields) -> None:  # noqa: ANN003
        self._log({"stage": stage, "age_s": self.age(), "at": time.strftime("%H:%M:%S"), **fields})

    def _spend(self, n: int = 1) -> None:
        cooldown.guard()
        if self.requests + n > self.max_requests:
            raise SystemExit(f"--max-requests {self.max_requests} reached; stopping (nothing more sent)")
        self.requests += n

    # -- the three operations ----------------------------------------------
    async def probe(self) -> dict:
        """One credential-free `init` with a freshly minted OTP. Returns the verdict and the SIM."""
        import srp._pysrp as srp  # noqa: PLC0415 - same SRP start gsa_init.py uses

        self._spend()
        headers = self.machine.headers()  # a new OTP every request: it is only good for 30 s
        provider = StaticAnisetteProvider(headers, self.client_info, serial=CLIENT_SERIAL,
                                          identity=CLIENT_IDENTITY)
        account = AsyncAppleAccount(provider, timeout=30)
        captured: dict[str, str] = {}
        send = account._http.post

        async def post(url, **kwargs):  # noqa: ANN001, ANN003, ANN202
            response = await send(url, **kwargs)
            sim = sim_from_response(response)
            if sim:
                captured["sim"] = sim
            return response

        account._http.post = post
        username = f"probe-{secrets.token_hex(4)}@example.invalid"
        _, a2k = srp.User(username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048).start_authentication()
        try:
            response = await account._gsa_request({"A2k": a2k, "u": username, "ps": ["s2k", "s2k_fo"], "o": "init"})
            status = response.get("Status") or {}
            verdict = {"ec": status.get("ec"), "hsc": status.get("hsc")}
        except Exception as error:  # noqa: BLE001 - a transport failure is a result, unless it is a 429
            if cooldown.looks_like_429(error):
                cooldown.note_429()
                raise Throttled(str(error)) from error
            verdict = {"error": f"{type(error).__name__}: {error}"[:200]}
        finally:
            await account.close()
        verdict["sim_b64"] = captured.get("sim")
        return verdict

    def synchronize(self, sim_b64: str) -> dict:
        """CoreADI's ADISynchronize, in-process on this machine's own store. No network."""
        out = self.machine.adi.synchronize(DS_ID, base64.b64decode(sim_b64))
        if out.ret != 0:
            return {"ret": out.ret}
        return {"ret": 0, "mid": out.outputs["mid"], "srm": out.outputs["srm"]}

    def sync_machine(self, mid: bytes, srm: bytes) -> dict:
        """POST the SRM. The verdict is `Response -> Status`."""
        if not self._urlbag_loaded:
            self._spend()
            self.gsa.load_urlbag()
            self._urlbag_loaded = True
        self._spend()
        stored = self.identity.get("routing")
        routing = int(stored) if stored and str(stored).isdigit() else None
        try:
            reply = self.gsa.sync_machine(base64.b64encode(mid).decode(), base64.b64encode(srm).decode(), routing)
        except GSAError as error:
            if cooldown.looks_like_429(error):
                raise Throttled(str(error)) from error
            return {"error": str(error)[:200]}
        status = reply.get("Status") or {}
        new_rinfo = reply.get("X-Apple-I-MD-RINFO")
        if new_rinfo is not None:
            try:
                self.machine.adi.set_routing(DS_ID, int(new_rinfo))
                self.machine._save_store()
                self.identity["routing"] = int(new_rinfo)
            except Exception:  # noqa: BLE001 - bookkeeping only
                pass
        return {"ec": status.get("ec"), "em": status.get("em"), "hsc": status.get("hsc"),
                "new_rinfo": new_rinfo, "keys": sorted(reply)}

    async def answer_sim(self, sim_b64: str) -> dict:
        """Synchronize + POST for a SIM already in hand (from any 434 answer). Returns the sync verdict."""
        done = self.synchronize(sim_b64)
        if done["ret"] != 0:
            self.log("synchronize", ret=done["ret"])
            return {"ok": False}
        self.log("synchronize", ret=0, srm_len=len(done["srm"]))
        verdict = self.sync_machine(done["mid"], done["srm"])
        self.log("syncMachine", **verdict)
        ok = verdict.get("ec") == 0
        if ok:
            self.last_sync = time.time()
            if self.on_synced:
                self.on_synced()
        return {"ok": ok, **verdict}

    async def ensure_fresh(self) -> str:
        """Make the machine accepted now. Returns 'accepted' (nothing needed), 'revived',
        'refused' (sync did not help), or 'unknown' (an answer we cannot classify)."""
        before = await self.probe()
        self.log("init-before", **{k: v for k, v in before.items() if k != "sim_b64"}, sim=bool(before.get("sim_b64")))
        if before.get("error"):
            return "unknown"
        if (before["ec"], before["hsc"]) != REFUSED:
            return "accepted" if before["ec"] in ACCEPTED_EC else "unknown"
        if self.last_sync is not None:
            self.log("lease", seconds_since_last_sync=round(time.time() - self.last_sync))
        if not before.get("sim_b64"):
            self.log("no-sim")
            return "refused"
        synced = await self.answer_sim(before["sim_b64"])
        if not synced["ok"]:
            return "refused"
        after = await self.probe()
        self.log("init-after", **{k: v for k, v in after.items() if k != "sim_b64"})
        return "revived" if after.get("ec") in ACCEPTED_EC else "refused"


async def hold(args: argparse.Namespace) -> int:
    resyncer = Resyncer(args.state, max_requests=args.max_requests)
    results = []
    for round_number in range(1, args.rounds + 1):
        if round_number > 1:
            await asyncio.sleep(args.delay)
        resyncer.log("round", n=round_number)
        results.append(await resyncer.ensure_fresh())
    print(json.dumps({"summary": results, "requests_sent": resyncer.requests}), flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state", required=True, type=Path, help="provisioned MacAnisette state directory")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--delay", type=float, default=45.0, help="seconds between rounds (default 45)")
    parser.add_argument("--max-requests", type=int, default=40)
    parser.add_argument("--dry-run", action="store_true", help="print the plan and the cooldown state; send nothing")
    parser.add_argument("--ignore-cooldown", action="store_true", help="do not refuse during a recorded cooldown")
    args = parser.parse_args()

    if not (args.state / "identity.json").exists():
        raise SystemExit(f"{args.state}/identity.json not found: that is not a provisioned state")
    worst = 1 + args.rounds * 3  # URL bag + 3 requests per round
    born = provisioned_at(args.state)
    print(f"state {args.state}: provisioned {time.time() - born:.0f} s ago; "
          f"{args.rounds} rounds, {args.delay:.0f} s apart, at most {worst} requests "
          f"(~{worst / max(1.0, args.rounds * args.delay / 60):.1f}/min), cap {args.max_requests}", flush=True)
    left = cooldown.remaining()
    print(f"cooldown: {'none' if left <= 0 else f'{left / 60:.0f} min left'}", flush=True)
    if args.dry_run:
        print("dry run: nothing sent")
        return 0
    cooldown.guard(args.ignore_cooldown)
    try:
        return asyncio.run(hold(args))
    except Throttled as error:
        print(json.dumps({"stage": "STOP", "reason": "HTTP 429", "detail": str(error)[:200]}), flush=True)
        print(f"429: stopped at once and recorded it; do not touch Apple for {cooldown.COOLDOWN_MINUTES} min",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
