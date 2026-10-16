"""One shared memory of Apple's HTTP 429, so no script talks to gsa.apple.com during a cooldown.

Every tool that sends Grand Slam / MidService requests calls `note_429()` when it meets a 429
and `guard()` before its first request. The marker is a file with the Unix time of the latest
429 (`/tmp/macadi/gsa-429`), so the memory survives between scripts and shells.

    .venv/bin/python tools/machoadi/cooldown.py            # show the state
    .venv/bin/python tools/machoadi/cooldown.py --clear    # forget it (only if you know better)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

MARKER = Path("/tmp/macadi/gsa-429")
COOLDOWN_MINUTES = 45  # shorter than Apple's own "an hour" advice; chosen by the user.


class Throttled(RuntimeError):
    """Apple answered HTTP 429; nothing more may be sent for the cooldown."""


def last_429() -> float | None:
    try:
        return float(MARKER.read_text().strip())
    except (OSError, ValueError):
        return None


def note_429(at: float | None = None) -> None:
    MARKER.parent.mkdir(parents=True, exist_ok=True)
    MARKER.write_text(f"{at if at is not None else time.time():.0f}\n")


def remaining(now: float | None = None) -> float:
    """Seconds until the cooldown is over (0 when it is)."""
    seen = last_429()
    if seen is None:
        return 0.0
    return max(0.0, seen + COOLDOWN_MINUTES * 60 - (now if now is not None else time.time()))


def guard(ignore: bool = False) -> None:
    left = remaining()
    if left > 0 and not ignore:
        raise SystemExit(
            f"cooldown: Apple answered 429 at {time.strftime('%H:%M:%S', time.localtime(last_429()))}; "
            f"wait {left / 60:.0f} more minutes (marker {MARKER}). Nothing was sent."
        )


def looks_like_429(error: object) -> bool:
    text = str(error)
    return "429" in text and ("HTTP 429" in text or "throttl" in text.lower() or "refused" in text.lower())


if __name__ == "__main__":
    if "--clear" in sys.argv:
        MARKER.unlink(missing_ok=True)
        print("cleared")
    else:
        seen = last_429()
        if seen is None:
            print("no 429 recorded")
        else:
            print(f"last 429 at {time.strftime('%H:%M:%S', time.localtime(seen))}; "
                  f"{remaining() / 60:.0f} minutes of cooldown left")
