#!/usr/bin/env python3
"""Stand-in node: post windowed custody chain entries to a retina-server.

Feeds deterministic synthetic frames into a HashChainBuilder, calls
close_if_due() every second, posts every closed (entry, batch) to
POST /api/custody/chain-entry and prints the server's verdict for each window.
It doubles as the reference host loop for the builder: register the key, add
frames, run the close timer, upload whatever closes, and commit the open window
on exit.

    python scripts/custody_server_test.py --server http://localhost:8000 --window-s 30 --windows 4

The state dir keeps the key and the chain log, so a rerun without --fresh
continues the chain. A rerun first waits until the chain's last window has
ended, so it never opens a window over one already committed. Frames are only
fed to the builder, never streamed to the server.

Exit status: 0 when every untampered window came back 2xx with verified and
batch_verified true and, with --tamper, the tampered window came back
unverified; 1 otherwise; 2 when registration fails or --fresh refuses to delete
the state dir; 130 after Ctrl-C, once the open window has been posted.
"""

from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import random
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from retina_custody import HashChainBuilder, HashChainEntry, SoftwareCryptoBackend, TimestampManager, canonicalize
from retina_custody.hash_chain import DEFAULT_WINDOW_S, GENESIS

DEFAULT_NODE_ID = "synth-cust-demo-01"
DEFAULT_STATE_DIR = "./custody-demo"
DEFAULT_SEED = 1
DEFAULT_TIMEOUT_S = 30.0
# Cloudflare in front of the test server refuses non-browser agents (403 1010).
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
)

REGISTER_PATH = "/api/custody/register"
CHAIN_ENTRY_PATH = "/api/custody/chain-entry"
STATUS_PATH = "/api/custody/status"

CLOSE_CHECK_S = 1.0  # close_if_due() cadence
TAMPER_AT = 3  # --tamper alters this posted window, counting from 1
STATE_ENTRIES = {"key.json", "chain"}  # everything this script writes in the state dir
CHAIN_LOG = "chain_log.jsonl"  # the builder's append-only log in its chain_dir
ISO_UTC = "%Y-%m-%dT%H:%M:%SZ"  # how the builder writes window_start and window_end

# Fixed and obviously synthetic (Null Island), so node_config_hash is stable.
NODE_CONFIG = {"rx_lat": 0.0, "rx_lon": 0.0, "fc_hz": 100_000_000, "fs_hz": 2_000_000}

# Frame timestamps count from a fixed epoch (2026-01-01T00:00:00Z), not the
# wall clock, so a seed always yields the same frames.
FRAME_EPOCH_MS = 1_767_225_600_000
MAX_DETECTIONS = 10


def say(message: str, err: bool = False) -> None:
    print(message, file=sys.stderr if err else None, flush=True)


# ── Frames and request bodies ────────────────────────────────────────────────


def make_frame(seed: int, index: int, period_ms: float) -> dict:
    """Frame `index` of the synthetic stream, shaped like the TCP DETECTION payload.

    A pure function of its arguments. Only Random.random() is used: it is the
    one method whose output Python keeps stable across versions.
    """
    rng = random.Random(f"{seed}:{index}")
    n = int(rng.random() * (MAX_DETECTIONS + 1))
    delay = [round(60.0 * rng.random(), 2) for _ in range(n)]  # us
    doppler = [round(600.0 * rng.random() - 300.0, 2) for _ in range(n)]  # Hz
    snr = [round(4.0 + 21.0 * rng.random(), 2) for _ in range(n)]  # dB
    return {"timestamp": FRAME_EPOCH_MS + round(index * period_ms), "delay": delay, "doppler": doppler, "snr": snr}


def register_body(node_id: str, crypto: SoftwareCryptoBackend) -> dict:
    return {
        "node_id": node_id,
        "public_key_pem": crypto.get_public_key_pem(),
        "fingerprint": crypto.get_public_key_fingerprint(),
        "serial_number": crypto.get_serial_number(),
        "signing_mode": crypto.signing_mode,
    }


def chain_entry_body(node_id: str, entry: HashChainEntry, batch: bytes) -> dict:
    return {"node_id": node_id, "entry": entry.to_dict(), "batch": batch.decode("ascii")}


def tamper_batch(batch: bytes) -> bytes | None:
    """`batch` with its first snr value raised by 1 dB and re-canonicalised, or None if it has no snr value."""
    frames = json.loads(batch)
    for frame in frames:
        if frame.get("snr"):
            frame["snr"][0] = round(frame["snr"][0] + 1.0, 2)
            return canonicalize(frames)
    return None


# ── HTTP ─────────────────────────────────────────────────────────────────────


@dataclass
class Reply:
    body: Any  # parsed JSON body, or None
    error: str  # empty only for a 2xx JSON response


def request_headers(api_key: str | None, user_agent: str) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": user_agent}
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def _excerpt(raw: bytes, limit: int = 200) -> str:
    text = " ".join(raw.decode("utf-8", "replace").split())
    return text if len(text) <= limit else text[:limit] + "..."


def http_json(method: str, url: str, payload: Any, headers: dict[str, str], timeout: float) -> Reply:
    """One request with a JSON body (when `payload` is not None). Never raises for HTTP or network errors."""
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers = headers | {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read()
            finally:
                exc.close()
    except (OSError, http.client.HTTPException) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        return Reply(None, f"network error: {reason or type(exc).__name__}")
    try:
        body = json.loads(raw)
    except ValueError:
        body = None
    if not 200 <= status < 300:
        return Reply(body, f"HTTP {status}: {_excerpt(raw)}")
    if body is None:
        return Reply(None, f"HTTP {status} without a JSON body: {_excerpt(raw)}")
    return Reply(body, "")


# ── Windows ──────────────────────────────────────────────────────────────────


@dataclass
class WindowResult:
    number: int
    entry: HashChainEntry
    size: int  # bytes of the batch as posted
    tampered: bool
    partial: bool
    error: str
    verified: Any = None
    batch_verified: Any = None
    reason: Any = None

    @property
    def passed(self) -> bool:
        if self.error:
            return False
        if self.tampered:
            return self.verified is False
        return self.verified is True and self.batch_verified is True

    def line(self) -> str:
        e = self.entry
        head = f"{'ok  ' if self.passed else 'FAIL'} #{self.number} {e.window_start} -> {e.window_end}"
        head += f"  n_detections={e.n_detections}  batch={self.size} B  "
        if self.error:
            tail = self.error
        else:
            tail = f"verified={self.verified} batch_verified={self.batch_verified} reason={self.reason}"
        marks = (" (partial)" if self.partial else "") + (" (tampered)" if self.tampered else "")
        return head + tail + marks


class WindowPoster:
    """Posts closed windows, applies --tamper, and keeps one result per window."""

    def __init__(self, call: Callable[..., Reply], node_id: str, tamper: bool):
        self._call = call
        self._node_id = node_id
        self._tamper_pending = tamper
        self.results: list[WindowResult] = []

    def post(self, entry: HashChainEntry, batch: bytes, partial: bool = False) -> WindowResult:
        number = len(self.results) + 1
        tampered = False
        if self._tamper_pending and number >= TAMPER_AT:
            altered = tamper_batch(batch)
            if altered is None:
                say(f"#{number} has no snr value to alter; --tamper moves to the next window that has one")
            else:
                batch, tampered, self._tamper_pending = altered, True, False
        reply = self._call("POST", CHAIN_ENTRY_PATH, chain_entry_body(self._node_id, entry, batch))
        body = reply.body if isinstance(reply.body, dict) else {}
        result = WindowResult(
            number=number,
            entry=entry,
            size=len(batch),
            tampered=tampered,
            partial=partial,
            error=reply.error,
            verified=body.get("verified"),
            batch_verified=body.get("batch_verified"),
            reason=body.get("reason"),
        )
        self.results.append(result)
        say(result.line())
        return result


def status_lines(body: Any, node_id: str) -> list[str]:
    blocks = {}
    if isinstance(body, dict):
        for name in ("node_keys", "chain_entries", "iq_commitments"):
            section = body.get(name)
            if isinstance(section, dict) and node_id in section:
                blocks[name] = section[node_id]
    if not blocks:
        return [f"status: {node_id} is not listed (the route lists only nodes with a public handle)"]
    return [f"status {name}: {json.dumps(value, sort_keys=True)}" for name, value in blocks.items()]


def summary_lines(results: list[WindowResult], frames_per_s: float) -> list[str]:
    passed = sum(r.passed for r in results)
    lines = [f"summary: {len(results)} windows posted, {passed} as expected, {len(results) - passed} not"]
    # The window closed on exit is cut short on purpose, so it is left out of the size spread.
    sized = [r.size for r in results if not r.partial] or [r.size for r in results]
    if sized:
        mean = sum(sized) / len(sized)
        lines.append(f"batch bytes per window: min {min(sized)} / max {max(sized)} / mean {mean:.0f} (n={len(sized)})")
    frames = sum(r.entry.n_detections for r in results)
    if frames:
        total = sum(r.size for r in results if r.entry.n_detections)
        per_frame = total / frames
        projected = per_frame * frames_per_s * DEFAULT_WINDOW_S
        lines.append(f"bytes per frame: {per_frame:.1f} ({frames} frames, {total} bytes)")
        lines.append(f"projected {DEFAULT_WINDOW_S} s batch at {frames_per_s:g} frames/s: {projected:,.0f} bytes")
    return lines


def clear_state_dir(path: str) -> str | None:
    """Delete a state dir this script made. Returns why it refused, or None."""
    if not os.path.lexists(path):
        return None
    if os.path.islink(path) or not os.path.isdir(path):
        return f"--fresh: refusing to delete {path}: not a plain directory"
    foreign = sorted(set(os.listdir(path)) - STATE_ENTRIES)
    if foreign:
        return f"--fresh: refusing to delete {path}: it holds {', '.join(foreign[:5])}, which this script did not write"
    shutil.rmtree(path)
    return None


def last_logged_entry(log_path: str) -> HashChainEntry | None:
    """The newest entry in the chain log, or None.

    Reads the log the way HashChainBuilder does when it resumes prev_hash: the
    last line that parses as an entry wins, and lines that do not are skipped.
    """
    try:
        with open(log_path) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            return HashChainEntry.from_dict(json.loads(line))
        except (ValueError, TypeError):
            continue
    return None


def wait_for_last_window(
    log_path: str, window_s: int, clock: Callable[[], float], sleep: Callable[[float], None]
) -> None:
    """Sleep until a new window can no longer overlap the chain's last one.

    The builder opens its first window on the window_s multiple holding the
    current time. The window posted on exit usually ends in the future, so a
    rerun before then would sign a second, different batch for that range.
    """
    entry = last_logged_entry(log_path)
    if entry is None:
        return
    try:
        last_end = datetime.strptime(entry.window_end, ISO_UTC).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return
    # The first multiple of this run's window_s at or after the last end; the
    # same instant unless --window-s changed between runs.
    resume_at = math.ceil(last_end / window_s) * window_s
    remaining = resume_at - clock()
    if remaining <= 0:
        return
    until = datetime.fromtimestamp(resume_at, tz=timezone.utc).strftime(ISO_UTC)
    say(
        f"waiting {math.ceil(remaining)} s until {until}, so the first window does not overlap "
        f"the chain's last one ({entry.window_start} -> {entry.window_end})"
    )
    while remaining > 0:
        sleep(remaining)
        remaining = resume_at - clock()


# ── Run ──────────────────────────────────────────────────────────────────────


def run(
    server: str,
    *,
    api_key: str | None = None,
    node_id: str = DEFAULT_NODE_ID,
    window_s: int = 60,
    frames_per_s: float = 2.0,
    windows: int = 5,
    state_dir: str = DEFAULT_STATE_DIR,
    fresh: bool = False,
    tamper: bool = False,
    tsa: bool = False,
    user_agent: str = DEFAULT_USER_AGENT,
    seed: int = DEFAULT_SEED,
    timeout: float = DEFAULT_TIMEOUT_S,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run the stand-in node and return the exit status.

    `clock` is the wall clock the builder windows on, which the rerun wait also
    reads; `monotonic` and `sleep` pace the frame loop, and `sleep` the wait.
    Tests pass fakes for all three.
    """
    base = server.rstrip("/")
    headers = request_headers(api_key, user_agent)

    def call(method: str, path: str, payload: Any = None) -> Reply:
        return http_json(method, base + path, payload, headers, timeout)

    # 1. The key. It is reused across runs, so the chain continues.
    if fresh:
        refusal = clear_state_dir(state_dir)
        if refusal:
            say(refusal, err=True)
            return 2
    crypto = SoftwareCryptoBackend(key_file=os.path.join(state_dir, "key.json"))

    # 2. Register it.
    reply = call("POST", REGISTER_PATH, register_body(node_id, crypto))
    if reply.error:
        say(f"register {node_id} at {base} failed: {reply.error}", err=True)
        return 2
    say(f"registered {node_id} at {base} (fingerprint {crypto.get_public_key_fingerprint()})")

    # 3. The builder, resuming any chain already in the state dir.
    chain_dir = os.path.join(state_dir, "chain")
    builder = HashChainBuilder(
        node_id,
        crypto,
        NODE_CONFIG,
        chain_dir=chain_dir,
        window_s=window_s,
        timestamper=TimestampManager() if tsa else None,
        clock=clock,
    )
    origin = "genesis" if builder.prev_hash == GENESIS else f"prev_hash {builder.prev_hash[:12]}..."
    say(f"chain from {origin}: {windows} windows of {window_s} s at {frames_per_s:g} frames/s, then the open one")

    poster = WindowPoster(call, node_id, tamper)

    # A rerun opens no window before the last committed one has ended.
    interrupted = False
    try:
        wait_for_last_window(os.path.join(chain_dir, CHAIN_LOG), window_s, clock, sleep)
    except KeyboardInterrupt:
        interrupted = True
        say("interrupted while waiting: no window is open, so nothing is posted")

    # 4-5. Frames on a monotonic schedule, close_if_due() about every second.
    # Frame k is due at start + k * period; a late loop catches up.
    period = 1.0 / frames_per_s
    period_ms = 1000.0 / frames_per_s
    start = monotonic()
    index = 0
    closes = 0
    next_frame = start
    next_check = start + CLOSE_CHECK_S
    try:
        while not interrupted and closes < windows:
            now = monotonic()
            while next_frame <= now and closes < windows:
                closed = builder.add_detection(make_frame(seed, index, period_ms))
                index += 1
                next_frame = start + index * period
                if closed is not None:
                    poster.post(*closed)
                    closes += 1
            if next_check <= now and closes < windows:
                closed = builder.close_if_due()
                next_check = now + CLOSE_CHECK_S
                if closed is not None:
                    poster.post(*closed)
                    closes += 1
            if closes < windows:
                sleep(max(0.0, min(next_frame, next_check) - monotonic()))
    except KeyboardInterrupt:
        interrupted = True
        say("interrupted: committing the open window")

    # 6. Commit the open window, then show what the server holds for this node.
    closed = builder.close_window()
    if closed is not None:
        poster.post(*closed, partial=True)
    reply = call("GET", STATUS_PATH)
    for line in [f"status: {reply.error}"] if reply.error else status_lines(reply.body, node_id):
        say(line)

    code = 0 if all(r.passed for r in poster.results) else 1
    if tamper and not any(r.tampered for r in poster.results):
        say("--tamper: no posted window had an snr value to alter")
        code = 1
    for line in summary_lines(poster.results, frames_per_s):
        say(line)
    return 130 if interrupted else code


# ── CLI ──────────────────────────────────────────────────────────────────────


def _server_url(value: str) -> str:
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise argparse.ArgumentTypeError(f"expected an http(s) origin such as http://localhost:8000, got {value!r}")
    return value.rstrip("/")


def _positive(kind: type) -> Callable[[str], Any]:
    def parse(value: str):
        try:
            number = kind(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not a {kind.__name__}: {value!r}") from None
        if not (math.isfinite(number) and number > 0):
            raise argparse.ArgumentTypeError(f"must be a positive number: {value!r}")
        return number

    return parse


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--server", required=True, type=_server_url, help="retina-server API origin")
    p.add_argument(
        "--api-key",
        default=os.environ.get("RADAR_API_KEY") or None,
        help="sent as X-API-Key (default: $RADAR_API_KEY; no header when neither is set)",
    )
    p.add_argument(
        "--node-id",
        default=DEFAULT_NODE_ID,
        help="node id to register and chain under (default: %(default)s). Keep the synth- prefix: "
        "/api/custody/status lists only nodes with a public handle, and synthetic ids are published as themselves",
    )
    p.add_argument("--window-s", type=_positive(int), default=60, help="window length in seconds (default: 60)")
    p.add_argument("--frames-per-s", type=_positive(float), default=2.0, help="frame rate (default: 2)")
    p.add_argument(
        "--windows", type=_positive(int), default=5, help="windows to close before the partial one on exit (default: 5)"
    )
    p.add_argument(
        "--state-dir",
        default=DEFAULT_STATE_DIR,
        help="key and chain log, reused across runs so the chain continues (default: %(default)s)",
    )
    p.add_argument(
        "--fresh",
        action="store_true",
        help="delete the state dir first: new key, chain from genesis. A server still holding this node id's "
        "verified chain rejects the first fresh window with prev_hash mismatch, so pair it with a new --node-id",
    )
    p.add_argument(
        "--tamper",
        action="store_true",
        help=f"change one snr value in posted window {TAMPER_AT}'s batch after signing and expect it back unverified",
    )
    p.add_argument("--tsa", action="store_true", help="timestamp each entry with DigiCert TSA and OpenTimestamps")
    p.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent header; Cloudflare refuses non-browser agents with 403 1010 (default: desktop Chrome)",
    )
    p.add_argument("--seed", type=int, default=DEFAULT_SEED, help="frame seed (default: %(default)s)")
    p.add_argument(
        "--timeout",
        type=_positive(float),
        default=DEFAULT_TIMEOUT_S,
        help="per-request timeout in seconds (default: 30)",
    )
    args = p.parse_args(argv)
    if args.tamper and args.windows + 1 < TAMPER_AT:
        p.error(f"--tamper alters posted window {TAMPER_AT}, so it needs --windows {TAMPER_AT - 1} or more")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return run(
        args.server,
        api_key=args.api_key,
        node_id=args.node_id,
        window_s=args.window_s,
        frames_per_s=args.frames_per_s,
        windows=args.windows,
        state_dir=args.state_dir,
        fresh=args.fresh,
        tamper=args.tamper,
        tsa=args.tsa,
        user_agent=args.user_agent,
        seed=args.seed,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    sys.exit(main())
