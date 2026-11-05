"""Tests for scripts/custody_server_test.py against a local stub of retina-server's custody routes.

The stub verifies every chain entry with HashChainVerifier against the key it
was registered with, holds the last verified entry_hash as the expected
prev_hash and refuses a stale window behind an unverified tail, the way the
server does. Time is faked, so a run of several windows takes milliseconds, and
nothing leaves 127.0.0.1.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import socket
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from retina_custody import HashChainEntry, HashChainVerifier, SoftwareCryptoBackend, canonicalize

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "custody_server_test.py"
_spec = importlib.util.spec_from_file_location("custody_server_test", SCRIPT)
cst = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cst  # dataclasses look their module up here
_spec.loader.exec_module(cst)

T0 = 1_800_000_000  # a multiple of 60 and 900
NODE = cst.DEFAULT_NODE_ID
REGISTER, CHAIN_ENTRY, STATUS = cst.REGISTER_PATH, cst.CHAIN_ENTRY_PATH, cst.STATUS_PATH


class StubServer:
    """Answers the custody routes like retina-server, verifying entries for real."""

    def __init__(self):
        self.reset()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.serve(self)

            def do_GET(self):
                outer.serve(self)

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def reset(self):
        self.requests: list[dict] = []
        self.keys: dict[str, str] = {}  # node_id -> PEM from /register
        self.chains: dict[str, list[dict]] = {}  # node_id -> stored entries with the verdict
        self.register_reply: tuple[int, bytes] | None = None  # answered instead of registering
        self.force_status: dict[int, int] = {}  # chain-entry post number -> status; nothing stored
        self.force_verdict: dict[int, bool] = {}  # chain-entry post number -> verdict answered and stored
        self.drop: set[int] = set()  # chain-entry post numbers answered by closing the connection
        self.hidden: set[str] = set()  # node ids left out of /status

    def posts(self) -> list[dict]:
        return [r for r in self.requests if r["path"] == CHAIN_ENTRY]

    def verdicts(self, node_id: str = NODE) -> list[bool]:
        return [e["_verified"] for e in self.chains.get(node_id, [])]

    def serve(self, h: BaseHTTPRequestHandler):
        raw = h.rfile.read(int(h.headers.get("Content-Length", 0)))
        body = json.loads(raw) if raw else None
        headers = {k.lower(): v for k, v in h.headers.items()}
        self.requests.append({"method": h.command, "path": h.path, "headers": headers, "body": body})
        if (h.command, h.path) == ("POST", REGISTER):
            status, reply = self.register(body)
        elif (h.command, h.path) == ("POST", CHAIN_ENTRY):
            number = len(self.posts())
            if number in self.drop:
                h.close_connection = True
                return
            status, reply = self.chain_entry(body, number)
        elif (h.command, h.path) == ("GET", STATUS):
            status, reply = 200, self.status()
        else:
            status, reply = 404, {"detail": "Not Found"}
        payload = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
        h.send_response(status)
        h.send_header("Content-Length", str(len(payload)))
        h.end_headers()
        h.wfile.write(payload)

    def register(self, body: dict) -> tuple[int, dict | bytes]:
        if self.register_reply is not None:
            return self.register_reply
        self.keys[body["node_id"]] = body["public_key_pem"]
        return 200, {"status": "registered", "node_id": body["node_id"], "signing_mode": body["signing_mode"]}

    def chain_entry(self, body: dict, number: int) -> tuple[int, dict]:
        if number in self.force_status:
            return self.force_status[number], {"detail": "forced"}
        try:
            entry = HashChainEntry.from_dict(body["entry"])
        except (KeyError, TypeError) as exc:
            return 422, {"detail": f"malformed entry: {exc}"}
        node_id, batch = body["node_id"], body.get("batch")
        chain = self.chains.setdefault(node_id, [])
        # An unverified tail does not anchor the next entry.
        expected_prev = chain[-1]["entry_hash"] if chain and chain[-1]["_verified"] else ""
        if entry.node_id != node_id:
            verified, reason = False, "node_id mismatch"
        elif not expected_prev and self.stale(entry, chain):
            verified, reason = False, "stale window: not after the last verified window"
        else:
            batch_bytes = None if batch is None else batch.encode("utf-8")
            verified, reason = HashChainVerifier(self.keys.get).verify_entry(entry, batch_bytes, expected_prev)
        if number in self.force_verdict:
            verified, reason = self.force_verdict[number], "forced"
        gap = bool(chain) and entry.window_start != chain[-1]["window_end"]
        chain.append(entry.to_dict() | {"_verified": verified, "_reason": reason, "_gap": gap})
        return 200, {
            "status": "stored",
            "node_id": node_id,
            "entry_hash": entry.entry_hash,
            "verified": verified,
            "reason": reason,
            "batch_verified": None if batch is None else verified,
        }

    @staticmethod
    def stale(entry: HashChainEntry, chain: list[dict]) -> bool:
        """Whether the entry ends no later than the newest verified window held."""
        last = next((e for e in reversed(chain) if e["_verified"]), None)
        return last is not None and epoch(entry.window_end) <= epoch(last["window_end"])

    def status(self) -> dict:
        listed = [n for n in self.keys if n not in self.hidden]
        return {
            "registered_nodes": len(listed),
            "node_keys": {n: {"signing_mode": "software"} for n in listed},
            "chain_entries": {
                n: {
                    "count": len(c),
                    "latest_window_end": c[-1]["window_end"],
                    "latest_verified": c[-1]["_verified"],
                    "verified": sum(e["_verified"] for e in c),
                    "gaps": sum(e["_gap"] for e in c),
                }
                for n, c in self.chains.items()
                if c and n not in self.hidden
            },
            "iq_commitments": {},
        }


@pytest.fixture(scope="module")
def _stub():
    with StubServer() as s:
        yield s


@pytest.fixture()
def stub(_stub):
    _stub.reset()
    return _stub


class FakeTime:
    """Wall and monotonic clocks that move only when the script sleeps."""

    def __init__(self, wall: float = T0 + 15.0, interrupt_at: float | None = None):
        self.wall = wall
        self.mono = 1000.0
        self.interrupt_at = interrupt_at
        self.limit = wall + 100_000
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def sleep(self, seconds: float):
        assert seconds >= 0
        self.sleeps.append(seconds)
        self.wall += seconds
        self.mono += seconds
        if self.interrupt_at is not None and self.wall >= self.interrupt_at:
            self.interrupt_at = None
            raise KeyboardInterrupt
        if self.wall > self.limit:
            raise RuntimeError("fake clock ran away: the run never finished")


def run_script(stub: StubServer, tmp_path: Path, clock: FakeTime | None = None, **kwargs) -> int:
    clock = clock or FakeTime()
    kwargs.setdefault("state_dir", str(tmp_path / "state"))
    kwargs.setdefault("window_s", 60)
    kwargs.setdefault("frames_per_s", 2.0)
    kwargs.setdefault("windows", 3)
    return cst.run(stub.url, clock=clock.time, monotonic=clock.monotonic, sleep=clock.sleep, **kwargs)


def chain_log(state_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (state_dir / "chain" / "chain_log.jsonl").read_text().splitlines()]


def has_snr(batch: str) -> bool:
    return any(frame["snr"] for frame in json.loads(batch))


def batch_matches(entry: dict, batch: str) -> bool:
    return hashlib.sha256(batch.encode("utf-8")).hexdigest() == entry["detections_hash"]


def epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def unused_port_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


# ── Frames ───────────────────────────────────────────────────────────────────


class TestFrames:
    def test_pure_function_of_seed_index_period(self):
        assert cst.make_frame(7, 3, 500.0) == cst.make_frame(7, 3, 500.0)
        assert [cst.make_frame(7, i, 500.0) for i in range(20)] != [cst.make_frame(8, i, 500.0) for i in range(20)]

    def test_default_seed_is_pinned(self):
        # Fails if Python's Random ever changes the sequence, which would break
        # byte-identical batches across versions.
        frames = [cst.make_frame(cst.DEFAULT_SEED, i, 500.0) for i in range(10)]
        digest = hashlib.sha256(canonicalize(frames)).hexdigest()
        assert digest == "0d7555c6e857cda5117d57c88c305ab52be6f1ec0fb214880cc9f7c7a7d00a8b"

    def test_shaped_like_a_detection_payload(self):
        period_ms = 1000 / 3
        frames = [cst.make_frame(cst.DEFAULT_SEED, i, period_ms) for i in range(200)]
        for i, frame in enumerate(frames):
            assert set(frame) == {"timestamp", "delay", "doppler", "snr"}
            assert type(frame["timestamp"]) is int
            assert frame["timestamp"] == cst.FRAME_EPOCH_MS + round(i * period_ms)
            assert len(frame["delay"]) == len(frame["doppler"]) == len(frame["snr"])
        lengths = [len(f["snr"]) for f in frames]
        assert 0 in lengths and max(lengths) >= 5 and len(set(lengths)) > 5


# ── Runs against the stub ────────────────────────────────────────────────────


class TestWireShape:
    def test_register_body(self, stub, tmp_path):
        assert run_script(stub, tmp_path, windows=1) == 0
        (reg,) = [r for r in stub.requests if r["path"] == REGISTER]
        crypto = SoftwareCryptoBackend(key_file=str(tmp_path / "state" / "key.json"))
        assert reg["body"] == {
            "node_id": NODE,
            "public_key_pem": crypto.get_public_key_pem(),
            "fingerprint": crypto.get_public_key_fingerprint(),
            "serial_number": crypto.get_serial_number(),
            "signing_mode": "software",
        }
        assert reg["headers"]["content-type"] == "application/json"

    def test_chain_entry_bodies_are_the_section_2_shape(self, stub, tmp_path):
        assert run_script(stub, tmp_path) == 0
        posts = stub.posts()
        assert len(posts) == 4
        for req in posts:
            assert req["headers"]["content-type"] == "application/json"
            body = req["body"]
            assert set(body) == {"node_id", "entry", "batch"}
            assert body["node_id"] == body["entry"]["node_id"] == NODE
            assert body["entry"] == HashChainEntry.from_dict(body["entry"]).to_dict()
            assert isinstance(body["batch"], str)
            assert batch_matches(body["entry"], body["batch"])
            assert body["batch"] == canonicalize(json.loads(body["batch"])).decode("ascii")
            assert len(json.loads(body["batch"])) == body["entry"]["n_detections"]
        entries = [p["body"]["entry"] for p in posts]
        assert entries == chain_log(tmp_path / "state")  # exactly what the builder signed and kept
        assert entries[0]["prev_hash"] == "genesis"
        assert all(b["prev_hash"] == a["entry_hash"] for a, b in zip(entries, entries[1:]))

    @pytest.mark.parametrize("key", ["k-123", None, ""])
    def test_api_key_header_only_when_given(self, stub, tmp_path, key):
        assert run_script(stub, tmp_path, api_key=key, windows=1) == 0
        assert len(stub.requests) == 4  # register, two windows, status
        assert [r["headers"].get("x-api-key") for r in stub.requests] == [key or None] * 4

    def test_browser_user_agent_by_default(self, stub, tmp_path):
        assert run_script(stub, tmp_path, windows=1) == 0
        assert {r["headers"]["user-agent"] for r in stub.requests} == {cst.DEFAULT_USER_AGENT}
        assert cst.DEFAULT_USER_AGENT.startswith("Mozilla/5.0 (") and " Chrome/" in cst.DEFAULT_USER_AGENT

    def test_custom_user_agent(self, stub, tmp_path):
        assert run_script(stub, tmp_path, windows=1, user_agent="probe/1.0") == 0
        assert {r["headers"]["user-agent"] for r in stub.requests} == {"probe/1.0"}


class TestExitStatus:
    def test_all_verified_exits_0(self, stub, tmp_path, capsys):
        assert run_script(stub, tmp_path) == 0
        assert stub.verdicts() == [True] * 4
        out = capsys.readouterr().out
        assert out.count("ok   #") == 4 and "FAIL" not in out
        assert "summary: 4 windows posted, 4 as expected, 0 not" in out
        assert "bytes per frame:" in out and "batch bytes per window: min" in out

    def test_unverified_untampered_window_exits_1_and_the_run_continues(self, stub, tmp_path, capsys):
        stub.force_verdict[2] = False
        assert run_script(stub, tmp_path) == 1
        assert len(stub.posts()) == 4
        assert stub.verdicts() == [True, False, True, True]
        out = capsys.readouterr().out
        assert "FAIL #2 " in out and "verified=False" in out
        assert any(r["path"] == STATUS for r in stub.requests)

    def test_non_2xx_exits_1_and_the_run_continues(self, stub, tmp_path, capsys):
        stub.force_status[2] = 500
        assert run_script(stub, tmp_path) == 1
        assert len(stub.posts()) == 4
        assert "FAIL #2 " in capsys.readouterr().out
        # The server stored nothing for #2, so #3 no longer links to its tail.
        assert stub.chains[NODE][1]["_reason"].startswith("prev_hash mismatch")

    def test_network_error_exits_1_and_the_run_continues(self, stub, tmp_path, capsys):
        stub.drop.add(2)
        assert run_script(stub, tmp_path) == 1
        assert len(stub.posts()) == 4
        out = capsys.readouterr().out
        assert "FAIL #2 " in out and "network error" in out

    @pytest.mark.parametrize(
        ("reply", "said"),
        [
            ((401, b'{"detail": "Invalid or missing X-API-Key"}'), "HTTP 401"),
            ((200, b"<!doctype html><title>dashboard</title>"), "HTTP 200 without a JSON body"),
        ],
    )
    def test_registration_failure_exits_2_before_any_window(self, stub, tmp_path, capsys, reply, said):
        stub.register_reply = reply
        assert run_script(stub, tmp_path) == 2
        assert stub.posts() == []
        assert said in capsys.readouterr().err

    def test_unreachable_server_exits_2(self, tmp_path):
        clock = FakeTime()
        code = cst.run(
            unused_port_url(),
            state_dir=str(tmp_path / "state"),
            clock=clock.time,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        assert code == 2


class TestTamper:
    def test_third_window_altered_after_signing_and_expected_unverified(self, stub, tmp_path, capsys):
        assert run_script(stub, tmp_path, tamper=True) == 0
        posts = stub.posts()
        entry, batch = posts[2]["body"]["entry"], posts[2]["body"]["batch"]
        assert entry == chain_log(tmp_path / "state")[2]  # the entry is untouched
        assert not batch_matches(entry, batch)
        assert all(batch_matches(p["body"]["entry"], p["body"]["batch"]) for i, p in enumerate(posts) if i != 2)
        # Rebuild the batch the entry was signed over, then diff: one snr value changed, nothing else.
        frames = json.loads(batch)
        originals = [
            cst.make_frame(cst.DEFAULT_SEED, (f["timestamp"] - cst.FRAME_EPOCH_MS) // 500, 500.0) for f in frames
        ]
        assert hashlib.sha256(canonicalize(originals)).hexdigest() == entry["detections_hash"]
        assert len(frames) == entry["n_detections"]
        ((frame, original),) = [(f, o) for f, o in zip(frames, originals) if f != o]
        assert {k: v for k, v in frame.items() if k != "snr"} == {k: v for k, v in original.items() if k != "snr"}
        assert len(frame["snr"]) == len(original["snr"])
        assert sum(a != b for a, b in zip(frame["snr"], original["snr"])) == 1
        assert batch == canonicalize(frames).decode("ascii")
        assert stub.verdicts() == [True, True, False, True]
        assert stub.chains[NODE][2]["_reason"].startswith("detections_hash mismatch")
        (line,) = [ln for ln in capsys.readouterr().out.splitlines() if ln.endswith("(tampered)")]
        assert line.startswith("ok   #3 ") and "reason=detections_hash mismatch" in line

    def test_tampered_window_wrongly_verified_exits_1(self, stub, tmp_path):
        stub.force_verdict[3] = True
        assert run_script(stub, tmp_path, tamper=True) == 1

    def test_moves_to_the_next_window_with_an_snr_value(self, stub, tmp_path, capsys):
        # A frame every 4 s into 1 s windows leaves windows 2 to 4 empty.
        clock = FakeTime(wall=T0 + 0.5)
        assert run_script(stub, tmp_path, clock=clock, tamper=True, window_s=1, frames_per_s=0.25, windows=8) == 0
        posts = [(p["body"]["entry"], p["body"]["batch"]) for p in stub.posts()]
        tampered = [n for n, (e, b) in enumerate(posts, 1) if not batch_matches(e, b)]
        assert len(tampered) == 1 and tampered[0] > 3
        assert not any(has_snr(b) for _, b in posts[2 : tampered[0] - 1])
        assert has_snr(posts[tampered[0] - 1][1])
        assert stub.verdicts() == [n not in tampered for n in range(1, len(posts) + 1)]
        assert "#3 has no snr value to alter" in capsys.readouterr().out


class TestState:
    def test_rerun_continues_the_chain(self, stub, tmp_path):
        clock = FakeTime()
        assert run_script(stub, tmp_path, clock=clock, windows=2) == 0
        last = chain_log(tmp_path / "state")[-1]["entry_hash"]
        first_run = len(stub.posts())
        assert run_script(stub, tmp_path, clock=FakeTime(clock.wall + 5), windows=2) == 0
        second = stub.posts()[first_run:]
        assert second[0]["body"]["entry"]["prev_hash"] == last
        # The stub held `last` as the expected prev_hash, so this proves the linkage.
        assert stub.verdicts() == [True] * len(stub.posts())
        pems = [r["body"]["public_key_pem"] for r in stub.requests if r["path"] == REGISTER]
        assert len(pems) == 2 and pems[0] == pems[1]

    def test_fresh_removes_old_state(self, stub, tmp_path):
        state = tmp_path / "state"
        assert run_script(stub, tmp_path) == 0
        old_pem, old_log = stub.keys[NODE], chain_log(state)
        # A server that has not seen the old chain: one that has would reject a
        # genesis entry under the same node id with prev_hash mismatch.
        stub.reset()
        assert run_script(stub, tmp_path, clock=FakeTime(T0 + 1000), fresh=True) == 0
        log = chain_log(state)
        assert stub.keys[NODE] != old_pem
        assert log[0]["prev_hash"] == "genesis" and len(log) == 4
        assert not {e["entry_hash"] for e in old_log} & {e["entry_hash"] for e in log}

    def test_fresh_refuses_a_directory_it_did_not_write(self, stub, tmp_path, capsys):
        state = tmp_path / "state"
        state.mkdir()
        (state / "notes.txt").write_text("keep me")
        assert run_script(stub, tmp_path, fresh=True) == 2
        assert (state / "notes.txt").read_text() == "keep me"
        assert stub.requests == []
        assert "refusing to delete" in capsys.readouterr().err

    def test_same_seed_gives_identical_batches(self, stub, tmp_path):
        def batches(node_id: str, seed: int) -> list[str]:
            state = str(tmp_path / f"{node_id}-{seed}")
            assert run_script(stub, tmp_path, node_id=node_id, seed=seed, state_dir=state) == 0
            return [p["body"]["batch"] for p in stub.posts() if p["body"]["node_id"] == node_id]

        first, second = batches("synth-a", 5), batches("synth-b", 5)
        assert len(first) == 4 and first == second
        assert batches("synth-c", 6) != first

    def test_partial_window_posted_on_exit(self, stub, tmp_path, capsys):
        clock = FakeTime()
        assert run_script(stub, tmp_path, clock=clock, windows=2) == 0
        entries = [p["body"]["entry"] for p in stub.posts()]
        assert len(entries) == 3
        assert entries[2]["window_start"] == entries[1]["window_end"]
        # Closed on exit, before its end: holds the one frame that closed window 2.
        assert epoch(entries[2]["window_end"]) > clock.wall
        assert entries[2]["n_detections"] == 1
        assert capsys.readouterr().out.count("(partial)") == 1

    def test_interrupt_commits_the_open_window(self, stub, tmp_path, capsys):
        clock = FakeTime(interrupt_at=T0 + 90)
        assert run_script(stub, tmp_path, clock=clock) == 130
        entries = [p["body"]["entry"] for p in stub.posts()]
        assert len(entries) == 2
        assert entries[1]["window_start"] == entries[0]["window_end"]
        assert entries[1]["n_detections"] == 60  # frames from T0+60 up to the interrupt at T0+90
        assert stub.verdicts() == [True, True]
        out = capsys.readouterr().out
        assert "interrupted" in out and "(partial)" in out and "status chain_entries" in out


class TestRerunWait:
    """A rerun must not open a window over the one the previous run posted on exit."""

    @staticmethod
    def first_run(stub, tmp_path, **kwargs) -> tuple[FakeTime, dict]:
        """Run once; return the clock where it stopped and the last logged entry."""
        clock = FakeTime()
        assert run_script(stub, tmp_path, clock=clock, windows=2, **kwargs) == 0
        last = chain_log(tmp_path / "state")[-1]
        assert epoch(last["window_end"]) > clock.wall  # the window posted on exit ends in the future
        return clock, last

    @staticmethod
    def rerun_entry(stub, before: int) -> dict:
        """The first entry the rerun posted, as the stub stored it with its verdict."""
        stored, posted = stub.chains[NODE][before], stub.posts()[before]["body"]["entry"]
        assert {k: v for k, v in stored.items() if not k.startswith("_")} == posted
        return stored

    @pytest.mark.parametrize("unverified_tail", [False, True], ids=["verified-tail", "after-refused-replay"])
    def test_rerun_right_after_a_run_waits_then_continues_contiguously(self, stub, tmp_path, capsys, unverified_tail):
        clock, last = self.first_run(stub, tmp_path)
        if unverified_tail:
            # A replay of the last window is refused and leaves the tail unverified, as before live run 4.
            replay = stub.posts()[-1]["body"]
            assert cst.http_json("POST", stub.url + CHAIN_ENTRY, replay, {}, 5).error == ""
            assert stub.verdicts()[-1] is False
        before = len(stub.chains[NODE])
        capsys.readouterr()
        rerun = FakeTime(clock.wall)
        assert run_script(stub, tmp_path, clock=rerun, windows=2) == 0
        assert rerun.sleeps[0] == pytest.approx(epoch(last["window_end"]) - clock.wall)
        assert f"waiting 60 s until {last['window_end']}, so the first window" in capsys.readouterr().out
        first = self.rerun_entry(stub, before)
        assert first["window_start"] == last["window_end"]
        assert first["prev_hash"] == last["entry_hash"]
        assert (first["_verified"], first["_reason"], first["_gap"]) == (True, "ok", False)
        assert all(stub.verdicts()[before:])

    def test_rerun_after_the_last_window_ended_does_not_wait(self, stub, tmp_path, capsys):
        _, last = self.first_run(stub, tmp_path)
        before = len(stub.chains[NODE])
        capsys.readouterr()
        rerun = FakeTime(epoch(last["window_end"]) + 5)
        assert run_script(stub, tmp_path, clock=rerun, windows=2) == 0
        assert "waiting" not in capsys.readouterr().out
        assert max(rerun.sleeps) <= cst.CLOSE_CHECK_S  # only the frame loop's own pacing
        first = self.rerun_entry(stub, before)
        assert first["window_start"] == last["window_end"] and first["prev_hash"] == last["entry_hash"]
        assert first["n_detections"] == 110  # frames from 5 s into the window: nothing was held back
        assert (first["_verified"], first["_gap"]) == (True, False)

    @pytest.mark.parametrize(
        "junk",
        [
            '{"node_id": "synth-cust-demo-01", "window_end": "20',  # cut off mid-append, no newline
            '{"window_end": "2099-01-01T00:00:00Z"}\n',  # JSON, but not an entry
        ],
        ids=["truncated", "not-an-entry"],
    )
    def test_malformed_last_line_falls_back_to_the_previous_entry(self, stub, tmp_path, capsys, junk):
        clock, last = self.first_run(stub, tmp_path)
        with (tmp_path / "state" / "chain" / cst.CHAIN_LOG).open("a") as f:
            f.write(junk)
        before = len(stub.chains[NODE])
        rerun = FakeTime(clock.wall)
        assert run_script(stub, tmp_path, clock=rerun, windows=1) == 0
        assert rerun.sleeps[0] == pytest.approx(epoch(last["window_end"]) - clock.wall)
        first = self.rerun_entry(stub, before)
        assert first["window_start"] == last["window_end"] and first["prev_hash"] == last["entry_hash"]
        assert (first["_verified"], first["_gap"]) == (True, False)

    @pytest.mark.parametrize(
        "log", [None, "", 'not json\n{"window_end": "2099-01-01T00:00:00Z"}\n'], ids=["no-log", "empty", "no-entry"]
    )
    def test_no_wait_without_a_logged_entry(self, stub, tmp_path, capsys, log):
        if log is not None:
            chain_dir = tmp_path / "state" / "chain"
            chain_dir.mkdir(parents=True)
            (chain_dir / cst.CHAIN_LOG).write_text(log)
        clock = FakeTime()
        assert run_script(stub, tmp_path, clock=clock, windows=1) == 0
        assert "waiting" not in capsys.readouterr().out
        assert max(clock.sleeps) <= cst.CLOSE_CHECK_S
        assert stub.posts()[0]["body"]["entry"]["prev_hash"] == "genesis"

    def test_interrupt_while_waiting_posts_nothing(self, stub, tmp_path, capsys):
        clock, _ = self.first_run(stub, tmp_path)
        log = (tmp_path / "state" / "chain" / cst.CHAIN_LOG).read_text()
        posted = len(stub.posts())
        capsys.readouterr()
        rerun = FakeTime(clock.wall, interrupt_at=clock.wall + 1)
        assert run_script(stub, tmp_path, clock=rerun, windows=2) == 130
        assert len(stub.posts()) == posted
        assert (tmp_path / "state" / "chain" / cst.CHAIN_LOG).read_text() == log  # nothing signed
        out = capsys.readouterr().out
        assert "interrupted while waiting" in out and "(partial)" not in out
        assert "status chain_entries" in out and "summary: 0 windows posted" in out

    def test_changed_window_s_waits_for_the_next_boundary(self, stub, tmp_path, capsys):
        clock, last = self.first_run(stub, tmp_path, window_s=30)
        assert epoch(last["window_end"]) == T0 + 90
        before = len(stub.chains[NODE])
        rerun = FakeTime(clock.wall)
        assert run_script(stub, tmp_path, clock=rerun, window_s=60, windows=1) == 0
        first = self.rerun_entry(stub, before)
        # 60 s windows start on multiples of 60: T0+60 would overlap the last window, T0+120 is the first that does not.
        assert epoch(first["window_start"]) == T0 + 120
        assert first["prev_hash"] == last["entry_hash"]
        assert (first["_verified"], first["_gap"]) == (True, True)  # an honest gap, not an overlap


class TestStatus:
    def test_prints_the_node_block(self, stub, tmp_path, capsys):
        assert run_script(stub, tmp_path) == 0
        out = capsys.readouterr().out
        assert 'status chain_entries: {"count": 4, ' in out and '"verified": 4' in out
        assert "status node_keys:" in out

    def test_says_when_the_node_is_not_listed(self, stub, tmp_path, capsys):
        stub.hidden.add(NODE)
        assert run_script(stub, tmp_path) == 0
        assert f"status: {NODE} is not listed" in capsys.readouterr().out


# ── CLI ──────────────────────────────────────────────────────────────────────


class TestCli:
    def test_help_explains_the_synth_prefix(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cst.main(["--help"])
        assert exc.value.code == 0
        assert "synth-" in capsys.readouterr().out

    def test_defaults_and_api_key_from_env(self, monkeypatch):
        calls = []
        monkeypatch.setattr(cst, "run", lambda server, **kw: calls.append((server, kw)) or 0)
        monkeypatch.setenv("RADAR_API_KEY", "from-env")
        assert cst.main(["--server", "http://127.0.0.1:8000/"]) == 0
        monkeypatch.delenv("RADAR_API_KEY")
        assert cst.main(["--server", "http://127.0.0.1:8000"]) == 0
        (server, kw), (_, kw2) = calls
        assert server == "http://127.0.0.1:8000"
        assert kw["api_key"] == "from-env" and kw2["api_key"] is None
        assert kw["node_id"] == "synth-cust-demo-01"
        assert (kw["window_s"], kw["frames_per_s"], kw["windows"]) == (60, 2.0, 5)
        assert kw["state_dir"] == "./custody-demo" and kw["seed"] == cst.DEFAULT_SEED
        assert not (kw["fresh"] or kw["tamper"] or kw["tsa"])

    @pytest.mark.parametrize(
        "argv",
        [
            [],
            ["--server", "ftp://example.invalid"],
            ["--server", "http://x", "--window-s", "0"],
            ["--server", "http://x", "--frames-per-s", "nan"],
            ["--server", "http://x", "--tamper", "--windows", "1"],
        ],
    )
    def test_rejects_unusable_arguments(self, argv, capsys):
        with pytest.raises(SystemExit) as exc:
            cst.main(argv)
        assert exc.value.code == 2
