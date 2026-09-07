"""Unit tests for Chain of Custody subsystem."""

import copy
import json
import os

import pytest

from retina_custody.canonical import canonicalize
from retina_custody.crypto_backend import SoftwareCryptoBackend
from retina_custody.hash_chain import HashChainBuilder, HashChainVerifier
from retina_custody.models import HashChainEntry, NodeIdentity

WINDOW_S = 900
T0 = 1_800_000_000  # aligned to a 15-minute boundary


@pytest.fixture()
def crypto(tmp_path):
    key_file = tmp_path / "node1" / "key.json"
    key_file.parent.mkdir()
    return SoftwareCryptoBackend(key_file=str(key_file))


@pytest.fixture()
def crypto_b(tmp_path):
    key_file = tmp_path / "node2" / "key.json"
    key_file.parent.mkdir()
    return SoftwareCryptoBackend(key_file=str(key_file))


class FakeClock:
    def __init__(self, t: float = T0 + 10):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float):
        self.t += s


class FakeTimestamper:
    def __init__(self):
        self.calls: list[str] = []

    def timestamp_entry(self, entry_hash: str):
        self.calls.append(entry_hash)
        return "tsa-" + entry_hash[:8], "ots-" + entry_hash[:8]


def make_builder(crypto, tmp_path, clock, **kwargs) -> HashChainBuilder:
    kwargs.setdefault("window_s", WINDOW_S)
    return HashChainBuilder(
        node_id="node-1",
        crypto=crypto,
        node_config={"lat": 1.0, "lon": 2.0},
        chain_dir=str(tmp_path / "chain"),
        clock=clock,
        **kwargs,
    )


def frame(i: int) -> dict:
    return {"timestamp": T0 * 1000 + i, "delay": [1.0 + i], "doppler": [2.0], "snr": [10.0]}


# ── 1. SoftwareCryptoBackend ─────────────────────────────────────────────────


class TestSoftwareCryptoBackend:
    def test_key_file_created(self, tmp_path):
        key_file = tmp_path / "node" / "key.json"
        key_file.parent.mkdir()
        SoftwareCryptoBackend(key_file=str(key_file))
        assert key_file.exists()

    def test_public_key_pem_format(self, crypto):
        assert crypto.get_public_key_pem().startswith("-----BEGIN PUBLIC KEY-----")

    def test_fingerprint_is_16_hex(self, crypto):
        assert len(crypto.get_public_key_fingerprint()) == 16

    def test_serial_starts_with_syn(self, crypto):
        assert crypto.get_serial_number().startswith("SYN-")

    def test_signing_mode_is_software(self, crypto):
        assert crypto.signing_mode == "software"

    def test_reloaded_key_matches(self, tmp_path):
        key_file = str(tmp_path / "reload" / "key.json")
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        c1 = SoftwareCryptoBackend(key_file=key_file)
        c2 = SoftwareCryptoBackend(key_file=key_file)
        assert c1.get_public_key_pem() == c2.get_public_key_pem()
        assert c1.get_public_key_fingerprint() == c2.get_public_key_fingerprint()


# ── 2. Signing & verification ────────────────────────────────────────────────


class TestSigningVerification:
    def test_sign_returns_bytes(self, crypto):
        sig = crypto.sign(b"hello")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_signature_verifies(self, crypto):
        data = b"detection frame data"
        sig = crypto.sign(data)
        assert crypto.verify(data, sig, crypto.get_public_key_pem())

    def test_tampered_data_fails(self, crypto):
        sig = crypto.sign(b"original")
        assert not crypto.verify(b"tampered", sig, crypto.get_public_key_pem())

    def test_sign_hex_returns_hex(self, crypto):
        hex_sig = crypto.sign_hex(b"data")
        bytes.fromhex(hex_sig)

    def test_hash_sha256_returns_64_hex(self, crypto):
        h = crypto.hash_sha256(b"data")
        assert len(h) == 64

    def test_hash_sha256_is_deterministic(self, crypto):
        assert crypto.hash_sha256(b"data") == crypto.hash_sha256(b"data")


class TestCrossKeyVerification:
    def test_wrong_key_rejects(self, crypto, crypto_b):
        sig = crypto.sign(b"data")
        assert not crypto_b.verify(b"data", sig, crypto_b.get_public_key_pem())


# ── 3. Canonicalization ──────────────────────────────────────────────────────


class TestCanonicalize:
    def test_different_key_order_same_output(self):
        a = canonicalize({"b": 1, "a": 2})
        b = canonicalize({"a": 2, "b": 1})
        assert a == b

    def test_no_whitespace(self):
        assert b" " not in canonicalize({"key": "value", "list": [1, 2, 3]})

    def test_sorted_keys(self):
        out = canonicalize({"z": 1, "a": 2, "m": 3})
        assert out.index(b'"a"') < out.index(b'"m"') < out.index(b'"z"')

    def test_list_of_frames(self):
        out = canonicalize([{"b": 1}, {"a": 2}])
        assert out == b'[{"b":1},{"a":2}]'


# ── 4. Hash chain builder ────────────────────────────────────────────────────


class TestHashChainBuilder:
    @pytest.fixture()
    def clock(self):
        return FakeClock()

    @pytest.fixture()
    def builder(self, crypto, tmp_path, clock):
        return make_builder(crypto, tmp_path, clock)

    def test_initial_prev_hash(self, builder):
        assert builder.prev_hash == "genesis"

    def test_no_pending(self, builder):
        assert builder.pending_detections == 0

    def test_add_detections(self, builder):
        builder.add_detection(frame(0))
        builder.add_detection(frame(1))
        assert builder.pending_detections == 2

    def test_rejects_non_positive_window(self, crypto, tmp_path, clock):
        with pytest.raises(ValueError):
            make_builder(crypto, tmp_path, clock, window_s=0)

    def test_close_window_returns_entry_and_batch(self, builder):
        frames = [frame(0), frame(1), frame(2)]
        for f in frames:
            builder.add_detection(f)
        entry, batch = builder.close_window()
        assert isinstance(entry, HashChainEntry)
        assert entry.n_detections == 3
        assert entry.prev_hash == "genesis"
        assert entry.signing_mode == "software"
        assert len(entry.entry_hash) == 64
        assert batch == canonicalize(frames)
        assert json.loads(batch) == frames
        assert builder.pending_detections == 0
        assert builder.prev_hash == entry.entry_hash

    def test_detections_hash_matches_batch(self, builder, crypto):
        builder.add_detection(frame(0))
        entry, batch = builder.close_window()
        assert entry.detections_hash == crypto.hash_sha256(batch)

    def test_window_bounds_are_aligned(self, builder):
        builder.add_detection(frame(0))
        entry, _ = builder.close_window()
        assert entry.window_start == "2027-01-15T08:00:00Z"
        assert entry.window_end == "2027-01-15T08:15:00Z"

    def test_close_window_with_no_window_open_returns_none(self, builder):
        assert builder.close_window() is None

    def test_close_if_due_before_boundary_returns_none(self, builder, clock):
        builder.add_detection(frame(0))
        clock.advance(WINDOW_S - 20)  # still inside the first window
        assert builder.close_if_due() is None
        assert builder.pending_detections == 1

    def test_close_if_due_after_boundary_closes(self, builder, clock):
        builder.add_detection(frame(0))
        clock.advance(WINDOW_S)
        entry, _ = builder.close_if_due()
        assert entry.n_detections == 1
        assert entry.window_start == "2027-01-15T08:00:00Z"
        assert builder.pending_detections == 0

    def test_empty_window_produces_entry(self, builder, clock):
        assert builder.close_if_due() is None  # opens the first window
        clock.advance(WINDOW_S)
        entry, batch = builder.close_if_due()
        assert entry.n_detections == 0
        assert batch == b"[]"

    def test_detection_inside_window_returns_none(self, builder):
        assert builder.add_detection(frame(0)) is None

    def test_detection_after_boundary_closes_and_returns_previous_window(self, builder, clock):
        builder.add_detection(frame(0))
        clock.advance(WINDOW_S)
        closed = builder.add_detection(frame(1))
        assert closed is not None
        entry, batch = closed
        assert entry.n_detections == 1
        assert json.loads(batch) == [frame(0)]
        chain = builder.get_chain()
        assert chain == [entry]
        assert builder.pending_detections == 1
        assert builder.get_latest_entry() is entry

    def test_frame_exactly_on_boundary_starts_new_window(self, builder, clock):
        builder.add_detection(frame(0))
        clock.t = T0 + WINDOW_S  # exactly the boundary, which is exclusive
        closed = builder.add_detection(frame(1))
        assert closed is not None
        assert closed[0].window_end == "2027-01-15T08:15:00Z"
        entry, batch = builder.close_window()
        assert entry.window_start == "2027-01-15T08:15:00Z"
        assert json.loads(batch) == [frame(1)]

    def test_clock_jump_closes_only_open_window_and_leaves_gap(self, builder, clock):
        builder.add_detection(frame(0))
        clock.advance(3 * WINDOW_S)
        e1, _ = builder.close_if_due()
        clock.advance(WINDOW_S)
        e2, _ = builder.close_if_due()
        assert e1.window_start == "2027-01-15T08:00:00Z"
        assert e2.window_start == "2027-01-15T08:45:00Z"  # 08:15 and 08:30 are a visible gap
        assert e2.prev_hash == e1.entry_hash

    def test_clock_step_backwards_does_not_reopen_window(self, builder, clock):
        builder.add_detection(frame(0))
        clock.advance(WINDOW_S)
        builder.close_if_due()  # closes window 0, opens window 1
        clock.advance(-WINDOW_S)  # clock stepped back into window 0
        assert builder.close_if_due() is None
        assert builder.add_detection(frame(1)) is None
        entry, batch = builder.close_window()
        assert entry.window_start == "2027-01-15T08:15:00Z"
        assert json.loads(batch) == [frame(1)]
        assert len(builder.get_chain()) == 2

    def test_unserializable_frame_rejected_without_side_effects(self, builder):
        builder.add_detection(frame(0))
        with pytest.raises(TypeError):
            builder.add_detection({"bad": object()})
        assert builder.pending_detections == 1
        entry, batch = builder.close_window()
        assert json.loads(batch) == [frame(0)]

    def test_persist_failure_leaves_state_unchanged(self, builder, monkeypatch):
        builder.add_detection(frame(0))

        def boom(entry):
            raise OSError("disk full")

        monkeypatch.setattr(builder, "_persist", boom)
        with pytest.raises(OSError):
            builder.close_window()
        assert builder.prev_hash == "genesis"
        assert builder.pending_detections == 1
        assert builder.get_chain() == []

        monkeypatch.undo()
        entry, batch = builder.close_window()
        assert entry.prev_hash == "genesis"
        assert json.loads(batch) == [frame(0)]

    def test_late_frame_goes_to_new_window(self, builder, clock):
        builder.add_detection(frame(0))
        clock.advance(WINDOW_S)
        builder.add_detection(frame(1))
        entry, batch = builder.close_window()
        assert entry.window_start == "2027-01-15T08:15:00Z"
        assert entry.prev_hash == builder.get_chain()[0].entry_hash
        assert json.loads(batch) == [frame(1)]

    def test_chain_links(self, builder, clock):
        builder.add_detection(frame(0))
        e1, _ = builder.close_window()
        clock.advance(WINDOW_S)
        builder.add_detection(frame(1))
        e2, _ = builder.close_window()
        assert e2.prev_hash == e1.entry_hash
        assert e2.window_start == e1.window_end

    def test_timestamper_called_with_entry_hash(self, crypto, tmp_path, clock):
        ts = FakeTimestamper()
        builder = make_builder(crypto, tmp_path, clock, timestamper=ts)
        builder.add_detection(frame(0))
        entry, _ = builder.close_window()
        assert ts.calls == [entry.entry_hash]
        assert entry.tsa_token == "tsa-" + entry.entry_hash[:8]
        assert entry.ots_proof == "ots-" + entry.entry_hash[:8]

    def test_no_timestamper_leaves_fields_none(self, builder):
        builder.add_detection(frame(0))
        entry, _ = builder.close_window()
        assert entry.tsa_token is None
        assert entry.ots_proof is None

    def test_chain_log_persisted(self, crypto, tmp_path, clock):
        ts = FakeTimestamper()
        builder = make_builder(crypto, tmp_path, clock, timestamper=ts)
        builder.add_detection(frame(0))
        entry, _ = builder.close_window()

        log_file = tmp_path / "chain" / "chain_log.jsonl"
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 1
        assert HashChainEntry.from_dict(json.loads(lines[0])) == entry

        state = json.loads((tmp_path / "chain" / "chain_state.json").read_text())
        assert state == {"last_hash": entry.entry_hash}


# ── 5. Hash chain verifier ───────────────────────────────────────────────────


class TestHashChainVerifier:
    @pytest.fixture()
    def chain(self, crypto, tmp_path):
        clock = FakeClock()
        builder = make_builder(crypto, tmp_path, clock, timestamper=FakeTimestamper())
        builder.add_detection(frame(0))
        builder.add_detection(frame(1))
        clock.advance(WINDOW_S)
        e1, b1 = builder.close_if_due()  # closes window 0, opens window 1
        clock.advance(WINDOW_S)
        e2, b2 = builder.close_if_due()  # closes empty window 1, opens window 2
        builder.add_detection(frame(2))
        e3, b3 = builder.close_window()
        return [e1, e2, e3], [b1, b2, b3]

    @pytest.fixture()
    def verifier(self, crypto):
        pem = crypto.get_public_key_pem()
        return HashChainVerifier(lambda node_id: pem if node_id == "node-1" else None)

    def test_first_entry_valid(self, verifier, chain):
        entries, batches = chain
        valid, reason = verifier.verify_entry(entries[0], batches[0])
        assert valid, reason

    def test_entry_valid_without_batch(self, verifier, chain):
        entries, _ = chain
        valid, reason = verifier.verify_entry(entries[0])
        assert valid, reason

    def test_second_entry_valid_with_linkage(self, verifier, chain):
        entries, batches = chain
        valid, reason = verifier.verify_entry(entries[1], batches[1], expected_prev_hash=entries[0].entry_hash)
        assert valid, reason

    def test_wrong_prev_hash_rejected(self, verifier, chain):
        entries, batches = chain
        valid, reason = verifier.verify_entry(entries[1], batches[1], expected_prev_hash="deadbeef" * 8)
        assert not valid
        assert "prev_hash" in reason

    def test_tampered_entry_field_rejected(self, verifier, chain):
        entries, batches = chain
        bad = copy.copy(entries[0])
        bad.n_detections = 99
        valid, reason = verifier.verify_entry(bad, batches[0])
        assert not valid
        assert "entry_hash" in reason

    def test_forged_signature_rejected(self, verifier, chain, crypto_b):
        entries, batches = chain
        bad = copy.copy(entries[0])
        bad.signature = crypto_b.sign_hex(b"whatever")
        valid, reason = verifier.verify_entry(bad, batches[0])
        assert not valid
        assert "signature" in reason

    def test_tampered_batch_rejected(self, verifier, chain):
        entries, batches = chain
        frames = json.loads(batches[0])
        frames[0]["delay"][0] += 0.001
        valid, reason = verifier.verify_entry(entries[0], canonicalize(frames))
        assert not valid
        assert "detections_hash" in reason

    def test_unknown_node_rejected(self, chain):
        entries, batches = chain
        verifier = HashChainVerifier(lambda node_id: None)
        valid, reason = verifier.verify_entry(entries[0], batches[0])
        assert not valid
        assert "no public key" in reason

    def test_full_chain_valid(self, verifier, chain):
        entries, batches = chain
        valid, issues = verifier.verify_chain(entries, batches)
        assert valid, issues

    def test_full_chain_valid_without_batches(self, verifier, chain):
        entries, _ = chain
        valid, issues = verifier.verify_chain(entries)
        assert valid, issues

    def test_missing_entry_breaks_chain(self, verifier, chain):
        entries, batches = chain
        valid, issues = verifier.verify_chain([entries[0], entries[2]], [batches[0], batches[2]])
        assert not valid
        assert len(issues) == 1
        assert "Entry 1" in issues[0]
        assert "prev_hash" in issues[0]

    def test_batches_length_mismatch(self, verifier, chain):
        entries, batches = chain
        valid, issues = verifier.verify_chain(entries, batches[:2])
        assert not valid
        assert issues


# ── 6. Chain recovery ────────────────────────────────────────────────────────


class TestChainRecovery:
    def test_recovered_prev_hash(self, crypto, tmp_path):
        clock = FakeClock()
        b1 = make_builder(crypto, tmp_path, clock)
        b1.add_detection(frame(0))
        e1, _ = b1.close_window()

        b2 = make_builder(crypto, tmp_path, clock)
        assert b2.prev_hash == e1.entry_hash

        clock.advance(WINDOW_S)
        b2.add_detection(frame(1))
        e2, _ = b2.close_window()
        assert e2.prev_hash == e1.entry_hash

        pem = crypto.get_public_key_pem()
        verifier = HashChainVerifier(lambda _: pem)
        valid, issues = verifier.verify_chain([e1, e2])
        assert valid, issues

    def test_recovers_from_log_when_state_file_corrupt(self, crypto, tmp_path):
        b1 = make_builder(crypto, tmp_path, FakeClock())
        b1.add_detection(frame(0))
        e1, _ = b1.close_window()
        (tmp_path / "chain" / "chain_state.json").write_text("{not json")

        b2 = make_builder(crypto, tmp_path, FakeClock())
        assert b2.prev_hash == e1.entry_hash

    def test_recovers_from_log_when_state_file_missing(self, crypto, tmp_path):
        b1 = make_builder(crypto, tmp_path, FakeClock())
        b1.add_detection(frame(0))
        e1, _ = b1.close_window()
        (tmp_path / "chain" / "chain_state.json").unlink()

        b2 = make_builder(crypto, tmp_path, FakeClock())
        assert b2.prev_hash == e1.entry_hash

    def test_partial_trailing_log_line_is_ignored(self, crypto, tmp_path):
        clock = FakeClock()
        b1 = make_builder(crypto, tmp_path, clock)
        b1.add_detection(frame(0))
        e1, _ = b1.close_window()
        log = tmp_path / "chain" / "chain_log.jsonl"
        with log.open("a") as f:
            f.write('{"node_id": "node-1", "window_start": "2027-01-15T08:15')  # power loss mid-append

        b2 = make_builder(crypto, tmp_path, clock)
        assert b2.prev_hash == e1.entry_hash

    def test_falls_back_to_state_file_when_log_missing(self, crypto, tmp_path):
        b1 = make_builder(crypto, tmp_path, FakeClock())
        b1.add_detection(frame(0))
        e1, _ = b1.close_window()
        (tmp_path / "chain" / "chain_log.jsonl").unlink()

        b2 = make_builder(crypto, tmp_path, FakeClock())
        assert b2.prev_hash == e1.entry_hash

    def test_fresh_directory_starts_at_genesis(self, crypto, tmp_path):
        assert make_builder(crypto, tmp_path, FakeClock()).prev_hash == "genesis"


# ── 7. Model serialization ───────────────────────────────────────────────────


class TestModelsSerialization:
    def test_hash_chain_entry_round_trip(self, crypto, tmp_path):
        builder = make_builder(crypto, tmp_path, FakeClock(), timestamper=FakeTimestamper())
        builder.add_detection(frame(0))
        entry, _ = builder.close_window()
        d = entry.to_dict()
        assert "tsa_token" in d
        restored = HashChainEntry.from_dict(json.loads(json.dumps(d)))
        assert restored == entry

    def test_hash_chain_entry_omits_none(self, crypto, tmp_path):
        builder = make_builder(crypto, tmp_path, FakeClock())
        builder.add_detection(frame(0))
        entry, _ = builder.close_window()
        d = entry.to_dict()
        assert "tsa_token" not in d
        assert "ots_proof" not in d
        assert HashChainEntry.from_dict(d) == entry

    def test_node_identity_round_trip(self, crypto):
        ident = NodeIdentity(
            node_id="node-1",
            public_key_pem=crypto.get_public_key_pem(),
            public_key_fingerprint=crypto.get_public_key_fingerprint(),
            serial_number=crypto.get_serial_number(),
            signing_mode=crypto.signing_mode,
            registered_at="2026-03-19T14:00:00Z",
        )
        restored = NodeIdentity.from_dict(ident.to_dict())
        assert restored == ident
        assert restored.serial_number == ident.serial_number
