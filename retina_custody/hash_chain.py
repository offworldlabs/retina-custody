"""
Windowed hash chain construction.

Detection frames are held in memory for the current time window (15 minutes
by default, aligned to the clock). When the window closes the node produces a
signed HashChainEntry committing to the canonical JSON of all frames in the
window, links it to the previous entry, and optionally attaches third-party
timestamps. The entry and the frame batch are then uploaded together to the
archive. Individual frames are not hashed or signed.

Chain structure:
  Window N-1                          Window N
  ┌───────────────────────┐          ┌──────────────────────────────┐
  │ prev_hash             │          │ prev_hash = hash(Window N-1) │
  │ detections_hash       │──hash──► │ detections_hash              │
  │ node config hash      │          │ node config hash             │
  │ firmware_version      │          │ firmware_version             │
  │ window_start/end      │          │ window_start/end             │
  └───────────────────────┘          └──────────────────────────────┘

Closing is time-driven. The host calls `close_if_due()` from a periodic timer
so that a quiet window still closes on the boundary and produces an entry with
zero detections. `add_detection()` also closes a stale window if a frame
arrives after the boundary before the timer fires; in that case it returns the
closed (entry, batch), which the host must upload just as it would for
`close_if_due()`. Windows only ever close forward: a clock step backwards does
not reopen an earlier window. If the clock jumps ahead by more than one window
(suspend, clock correction) only the open window is closed, and the gap is
visible in the archive as a window_start that does not equal the previous
window_end.

Only the chain log and a small state file are written to disk, once per
window, and the entry is written before in-memory state advances, so a failed
write leaves the frames pending for retry. Pending frames live in RAM until
the window closes. On restart the chain resumes from the last complete line
of the chain log, falling back to the state file, so the two cannot diverge.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from .canonical import canonicalize
from .crypto_backend import CryptoBackend
from .models import HashChainEntry
from .tsa_client import TimestampManager

logger = logging.getLogger(__name__)

FIRMWARE_VERSION = "1.0.0-synthetic"
DEFAULT_WINDOW_S = 15 * 60
GENESIS = "genesis"


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class HashChainBuilder:
    """Builds and maintains the windowed hash chain for a node.

    Accumulates detection frames during the current window. `close_window()`
    produces a signed HashChainEntry plus the canonical frame batch it commits
    to, and resets for the next window.
    """

    def __init__(
        self,
        node_id: str,
        crypto: CryptoBackend,
        node_config: dict,
        chain_dir: str = "",
        firmware_version: str = FIRMWARE_VERSION,
        window_s: int = DEFAULT_WINDOW_S,
        timestamper: TimestampManager | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self.node_id = node_id
        self.crypto = crypto
        self.node_config = node_config
        self.firmware_version = firmware_version
        self.window_s = window_s
        self.timestamper = timestamper
        self._clock = clock
        self._lock = threading.Lock()

        # Chain state
        self._prev_hash: str = GENESIS
        self._window_start: int | None = None  # epoch seconds, aligned to window_s
        self._frames: list[dict] = []
        self._chain: list[HashChainEntry] = []

        # Persistence directory
        self._chain_dir = chain_dir or os.path.join(os.path.dirname(__file__), "..", "coverage_data", "chains", node_id)
        os.makedirs(self._chain_dir, exist_ok=True)

        self._load_chain_state()

    # ── Persistence ──────────────────────────────────────────────────────────

    @property
    def _log_file(self) -> str:
        return os.path.join(self._chain_dir, "chain_log.jsonl")

    @property
    def _state_file(self) -> str:
        return os.path.join(self._chain_dir, "chain_state.json")

    def _load_chain_state(self):
        """Resume the chain after a restart.

        The chain log is authoritative: its last complete line is the last entry
        this node signed. The state file is a fallback for a missing or
        unreadable log. A partial trailing log line (power loss mid-append) is
        ignored; that entry never reached the caller, so the chain continues
        from the entry before it.
        """
        last_hash = self._last_logged_hash()
        source = "chain log"
        if last_hash is None:
            last_hash = self._state_file_hash()
            source = "state file"
        if last_hash is None:
            return
        self._prev_hash = last_hash
        logger.info("Resumed chain for %s from %s (prev_hash=%s...)", self.node_id, source, last_hash[:12])

    def _last_logged_hash(self) -> str | None:
        if not os.path.exists(self._log_file):
            return None
        try:
            with open(self._log_file) as f:
                lines = f.read().splitlines()
        except OSError as exc:
            logger.warning("Failed to read chain log for %s: %s", self.node_id, exc)
            return None
        for line in reversed(lines):
            try:
                return HashChainEntry.from_dict(json.loads(line)).entry_hash
            except (ValueError, TypeError):
                logger.warning("Ignoring unparseable chain log line for %s", self.node_id)
        return None

    def _state_file_hash(self) -> str | None:
        if not os.path.exists(self._state_file):
            return None
        try:
            with open(self._state_file) as f:
                return json.load(f)["last_hash"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("Failed to load chain state for %s: %s", self.node_id, exc)
            return None

    def _persist(self, entry: HashChainEntry):
        """Append the entry to the chain log, then atomically replace the state file."""
        with open(self._log_file, "a") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")
        tmp = self._state_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"last_hash": entry.entry_hash}, f)
        os.replace(tmp, self._state_file)

    # ── Window handling ──────────────────────────────────────────────────────

    def _window_for(self, ts: float) -> int:
        return int(ts // self.window_s) * self.window_s

    def add_detection(self, frame: dict) -> tuple[HashChainEntry, bytes] | None:
        """Record a detection frame in the current window.

        If the frame arrives after the current window's boundary, the stale
        window is closed first and its (entry, batch) is returned for upload;
        otherwise returns None. Raises TypeError or ValueError, without
        recording anything, if the frame is not JSON serializable.
        """
        canonicalize(frame)  # reject unserializable frames before they can wedge the window
        with self._lock:
            now = self._clock()
            closed = self._close_if_due_locked(now)
            if self._window_start is None:
                self._window_start = self._window_for(now)
            self._frames.append(frame)
            return closed

    def close_if_due(self) -> tuple[HashChainEntry, bytes] | None:
        """Close the current window if the clock has passed its end.

        Call this from a periodic timer. Returns the closed entry and batch, or
        None if the window is still open or no window has started. On the
        first call after startup this opens a window without closing one.
        """
        with self._lock:
            now = self._clock()
            closed = self._close_if_due_locked(now)
            if self._window_start is None:
                self._window_start = self._window_for(now)
            return closed

    def _close_if_due_locked(self, now: float) -> tuple[HashChainEntry, bytes] | None:
        # Only close forward. A clock step backwards keeps the current window open.
        if self._window_start is None or self._window_for(now) <= self._window_start:
            return None
        return self._close_window_locked()

    def close_window(self) -> tuple[HashChainEntry, bytes] | None:
        """Close the current window now, regardless of the clock.

        Returns (entry, batch) or None if no window is open. Use at shutdown
        so pending frames are committed before the process exits.
        """
        with self._lock:
            if self._window_start is None:
                return None
            return self._close_window_locked()

    def _close_window_locked(self) -> tuple[HashChainEntry, bytes]:
        window_start = self._window_start
        window_end = window_start + self.window_s
        frames = self._frames

        batch = canonicalize(frames)
        detections_hash = self.crypto.hash_sha256(batch)
        node_config_hash = self.crypto.hash_sha256(canonicalize(self.node_config))
        now_utc = datetime.now(timezone.utc).isoformat()

        entry_data = {
            "node_id": self.node_id,
            "window_start": _iso_utc(window_start),
            "window_end": _iso_utc(window_end),
            "prev_hash": self._prev_hash,
            "detections_hash": detections_hash,
            "n_detections": len(frames),
            "node_config_hash": node_config_hash,
            "firmware_version": self.firmware_version,
            "timestamp_utc": now_utc,
        }
        entry_canonical = canonicalize(entry_data)
        entry_hash = self.crypto.hash_sha256(entry_canonical)
        signature = self.crypto.sign_hex(entry_canonical)

        tsa_token = ots_proof = None
        if self.timestamper is not None:
            tsa_token, ots_proof = self.timestamper.timestamp_entry(entry_hash)

        entry = HashChainEntry(
            **entry_data,
            entry_hash=entry_hash,
            signature=signature,
            signing_mode=self.crypto.signing_mode,
            tsa_token=tsa_token,
            ots_proof=ots_proof,
        )

        # Persist first. If this raises, nothing has advanced: the frames stay
        # pending and the window stays open, so the next close retries.
        self._persist(entry)

        self._prev_hash = entry_hash
        self._chain.append(entry)
        self._frames = []
        self._window_start = None

        logger.info(
            "Chain entry for %s window=%s: %d detections, hash=%s...",
            self.node_id,
            entry.window_start,
            entry.n_detections,
            entry_hash[:12],
        )
        return entry, batch

    # ── Accessors ────────────────────────────────────────────────────────────

    def get_chain(self) -> list[HashChainEntry]:
        """Return all chain entries built during this session."""
        return list(self._chain)

    def get_latest_entry(self) -> HashChainEntry | None:
        return self._chain[-1] if self._chain else None

    @property
    def pending_detections(self) -> int:
        """Number of frames accumulated in the current (unclosed) window."""
        return len(self._frames)

    @property
    def prev_hash(self) -> str:
        return self._prev_hash


class HashChainVerifier:
    """Archive-side verification of hash chain entries.

    Verifies:
    1. Chain linkage (prev_hash matches the previous entry)
    2. Entry hash correctness
    3. Signature validity
    4. When the frame batch is supplied, that it matches detections_hash
       and n_detections
    """

    def __init__(self, get_public_key: Callable[[str], str | None]):
        self._get_key = get_public_key

    def verify_entry(
        self,
        entry: HashChainEntry,
        batch: bytes | None = None,
        expected_prev_hash: str = "",
    ) -> tuple[bool, str]:
        """Verify a single chain entry. Returns (valid, reason)."""
        if expected_prev_hash and entry.prev_hash != expected_prev_hash:
            return False, f"prev_hash mismatch: expected {expected_prev_hash[:12]}..., got {entry.prev_hash[:12]}..."

        entry_data = {
            "node_id": entry.node_id,
            "window_start": entry.window_start,
            "window_end": entry.window_end,
            "prev_hash": entry.prev_hash,
            "detections_hash": entry.detections_hash,
            "n_detections": entry.n_detections,
            "node_config_hash": entry.node_config_hash,
            "firmware_version": entry.firmware_version,
            "timestamp_utc": entry.timestamp_utc,
        }
        entry_canonical = canonicalize(entry_data)
        computed_hash = hashlib.sha256(entry_canonical).hexdigest()
        if computed_hash != entry.entry_hash:
            return False, f"entry_hash mismatch: computed {computed_hash[:12]}..., got {entry.entry_hash[:12]}..."

        pem = self._get_key(entry.node_id)
        if not pem:
            return False, f"no public key for node {entry.node_id}"

        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives import serialization as ser
            from cryptography.hazmat.primitives.asymmetric import ec

            pub_key = ser.load_pem_public_key(pem.encode())
            pub_key.verify(bytes.fromhex(entry.signature), entry_canonical, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False, "invalid signature"
        except Exception as exc:
            return False, f"verification error: {exc}"

        if batch is not None:
            batch_hash = hashlib.sha256(batch).hexdigest()
            if batch_hash != entry.detections_hash:
                return (
                    False,
                    f"detections_hash mismatch: computed {batch_hash[:12]}..., got {entry.detections_hash[:12]}...",
                )
            try:
                frames = json.loads(batch)
            except ValueError as exc:
                return False, f"batch is not valid JSON: {exc}"
            if not isinstance(frames, list) or len(frames) != entry.n_detections:
                return False, f"n_detections mismatch: batch has {len(frames) if isinstance(frames, list) else '?'}"

        return True, "ok"

    def verify_chain(
        self,
        entries: list[HashChainEntry],
        batches: list[bytes] | None = None,
    ) -> tuple[bool, list[str]]:
        """Verify a sequence of chain entries. Returns (all_valid, issues).

        `batches`, if given, must be parallel to `entries`.
        """
        if batches is not None and len(batches) != len(entries):
            return False, ["batches and entries have different lengths"]

        issues = []
        expected_prev = ""
        for i, entry in enumerate(entries):
            if i == 0 and entry.prev_hash == GENESIS:
                expected_prev = ""
            batch = batches[i] if batches is not None else None
            valid, reason = self.verify_entry(entry, batch, expected_prev)
            if not valid:
                issues.append(f"Entry {i} ({entry.window_start}): {reason}")
            expected_prev = entry.entry_hash

        return len(issues) == 0, issues
