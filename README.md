# retina-custody

Cryptographic chain of custody for RETINA passive radar detection data.

`retina_custody` is a small, dependency-light Python library (`cryptography` is the
only runtime dependency) that a RETINA node embeds to make its detection output
tamper-evident, and that an archive uses to verify what it receives. It was
extracted from the Tower-Finder backend and is published as a standalone package.

The design has three parts:

- **Windowed hash chain.** Detection frames are batched per clock-aligned time
  window (15 minutes by default). When a window closes the node hashes the
  canonical JSON of the batch, builds a `HashChainEntry` that links to the
  previous entry, signs it, and persists it. Individual frames are not hashed or
  signed.
- **Node-direct third-party timestamps.** Each entry hash can be submitted by the
  node itself to an RFC 3161 Timestamping Authority (DigiCert) and to
  OpenTimestamps calendar servers. Offworld Labs is not in the trust path.
- **IQ capture commitments.** A node keeps a short in-RAM circular buffer of raw
  IQ samples. On request it freezes a window, hashes and signs it, timestamps the
  hash, and produces a commitment that must be sent before the IQ bytes are
  uploaded.

The package does not include any network transport, server, or archive storage.
The host process that embeds it is responsible for calling the builder on a timer,
uploading the `(entry, batch)` pairs it returns, and storing node public keys.

## Architecture

The diagram shows the package as it exists today. Solid boxes are implemented
and tested. Dashed boxes are either placeholders or are implemented but not yet
wired into any caller.

```mermaid
flowchart TB
    subgraph host["Node host process (outside this package)"]
        frames["Detection frames (dict)"]
        timer["Periodic timer"]
        uploader["Uploader"]
    end

    subgraph node["retina_custody — node side"]
        direction TB
        canon["canonical.canonicalize()<br/>sorted keys · no whitespace · ASCII"]
        builder["hash_chain.HashChainBuilder<br/>windowed chain, 15 min default"]
        subgraph crypto["crypto_backend"]
            sw["SoftwareCryptoBackend<br/>P-256 ECDSA, key in synthetic_key.json"]
            hw["HardwareCryptoBackend<br/>ATECC608B · placeholder"]
        end
        subgraph ts["tsa_client"]
            tsm["TimestampManager"]
            tsa["TSAClient<br/>RFC 3161"]
            ots["OpenTimestampsClient"]
        end
        subgraph persist["chain_dir on disk"]
            log["chain_log.jsonl<br/>append-only, authoritative"]
            state["chain_state.json<br/>last_hash fallback"]
        end
        subgraph iq["iq_buffer"]
            ring["IQCircularBuffer<br/>2 min of IQ in RAM"]
            cap["IQCaptureManager<br/>freeze → hash → sign → TSA"]
        end
    end

    subgraph ext["Third-party timestamp services"]
        digicert["timestamp.digicert.com"]
        calendars["OpenTimestamps calendars<br/>a.pool / b.pool / eternitywall"]
    end

    subgraph archive["Archive (outside this package)"]
        verifier["hash_chain.HashChainVerifier"]
        keys["Node public keys<br/>(NodeIdentity)"]
        store["Stored entries + batches"]
    end

    frames -->|add_detection| builder
    timer -->|close_if_due| builder
    builder --> canon
    builder -->|hash_sha256 / sign_hex| crypto
    builder -->|timestamp_entry entry_hash| tsm
    tsm --> tsa --> digicert
    tsm --> ots --> calendars
    builder -->|append, then replace| log
    builder --> state
    log -.->|resume prev_hash on restart| builder
    builder -->|"(HashChainEntry, batch)"| uploader
    uploader --> store
    store --> verifier
    keys --> verifier

    ring --> cap
    cap --> crypto
    cap --> tsa
    cap -.->|"(IQCapturePackage, iq_bytes)"| uploader

    classDef placeholder stroke-dasharray: 5 5
    class hw,ring,cap placeholder
```

### What one chain entry commits to

Every hash and signature is computed over canonical JSON (`canonicalize()`:
sorted keys, no whitespace, `ensure_ascii`). Node and archive must agree on this
byte-for-byte, otherwise hashes will not match.

When a window closes, `HashChainBuilder` builds this dict, canonicalises it, and
hashes and signs the resulting bytes:

| Field | Meaning |
| --- | --- |
| `node_id` | Node identifier |
| `window_start`, `window_end` | ISO 8601 UTC, aligned to the window size, start inclusive, end exclusive |
| `prev_hash` | `entry_hash` of the previous entry, or `"genesis"` for the first |
| `detections_hash` | SHA-256 of the canonical JSON array of all frames in the window |
| `n_detections` | Number of frames in the window |
| `node_config_hash` | SHA-256 of the canonical node config at window close |
| `firmware_version` | Firmware string, `1.0.0-synthetic` by default |
| `timestamp_utc` | Creation time of the entry |

The resulting `HashChainEntry` adds `entry_hash`, `signature` (hex ECDSA P-256 /
SHA-256), `signing_mode` (`"software"` or `"hardware"`), and the optional
`tsa_token` and `ots_proof` (both base64).

```
Window N-1                          Window N
┌───────────────────────┐          ┌──────────────────────────────┐
│ prev_hash             │          │ prev_hash = hash(Window N-1) │
│ detections_hash       │──hash──► │ detections_hash              │
│ node config hash      │          │ node config hash             │
│ firmware_version      │          │ firmware_version             │
│ window_start/end      │          │ window_start/end             │
└───────────────────────┘          └──────────────────────────────┘
```

### Window lifecycle

Closing is time-driven and windows only ever close forward.

- `add_detection(frame)` records a frame in the open window. If the frame arrives
  after the window boundary, the stale window is closed first and its
  `(entry, batch)` is returned so the host can upload it. Frames that are not JSON
  serialisable are rejected before anything is recorded.
- `close_if_due()` should be called from a periodic timer. A quiet window still
  closes on the boundary and produces an entry with zero detections.
- `close_window()` closes the open window regardless of the clock. Use it at
  shutdown so pending frames are committed.
- A clock step backwards does not reopen an earlier window. A jump forward by
  more than one window closes only the open window, and the gap is visible in the
  archive as a `window_start` that does not equal the previous `window_end`.

### Persistence and recovery

Only two files are written, once per window, under `chain_dir`:

- `chain_log.jsonl`: one JSON line per entry, appended first. This is
  authoritative.
- `chain_state.json`: `{"last_hash": ...}`, written to a temp file and atomically
  replaced after the log append.

The entry is persisted before in-memory state advances. If the write fails the
frames stay pending and the window stays open, so the next close retries. On
restart the builder resumes `prev_hash` from the last complete line of the log,
falling back to the state file. A partial trailing log line from a power loss
mid-append is ignored.

Pending frames live only in RAM until the window closes. If `chain_dir` is not
given, the default is `coverage_data/chains/<node_id>` relative to the package's
parent directory.

### Verification

`HashChainVerifier` is the archive-side counterpart. Given a callback that
returns a node's PEM public key, `verify_entry()` checks, in order:

1. `prev_hash` matches the expected previous entry hash (when supplied).
2. `entry_hash` equals the SHA-256 of the recomputed canonical entry.
3. The ECDSA signature verifies against the node's public key.
4. When the frame batch is supplied, its SHA-256 equals `detections_hash` and
   it is a JSON list of length `n_detections`.

`verify_chain()` walks a list of entries, threading each `entry_hash` into the
next entry's expected `prev_hash`, and returns every issue found. TSA tokens and
OpenTimestamps proofs are carried on the entry but are not validated by this
package.

### Timestamping

`TimestampManager.timestamp_entry(entry_hash)` calls both services and returns
`(tsa_token, ots_proof)`. Either may be `None` if a service is unavailable, and
a failure in one does not block the other.

- `TSAClient` builds a minimal DER-encoded RFC 3161 `TimeStampReq` for a SHA-256
  digest with a random nonce and `certReq=TRUE`, posts it to
  `http://timestamp.digicert.com`, and accepts the response only if its
  `PKIStatus` is `granted` or `grantedWithMods` and a `timeStampToken` is present.
- `OpenTimestampsClient` posts the raw digest to each calendar server in turn
  and returns the first non-empty proof. Proofs start out pending; the calendar
  upgrades them to full Bitcoin proofs asynchronously. Upgrading is not handled
  here.

Requests are made directly from the node with a 15 second timeout.

### IQ capture

`IQCircularBuffer` holds `(timestamp_ms, chunk)` tuples in a deque and evicts
anything older than its duration (120 s by default). In synthetic mode it fills
itself with 1 KiB random chunks once per second for protocol testing. Nothing is
written to disk.

`IQCaptureManager.capture(window_start_ms, window_end_ms)` freezes the buffer for
the window, hashes the bytes, signs them, requests a TSA timestamp for the hash,
and returns an `IQCapturePackage` plus the raw bytes. The intended ordering is
that the caller sends the package (hash, signature, TSA token) to the server and
waits for acknowledgment before uploading the IQ data, so the commitment always
precedes the data.

## Usage

Node side:

```python
from retina_custody import HashChainBuilder, SoftwareCryptoBackend, TimestampManager

crypto = SoftwareCryptoBackend(key_file="node-1/key.json")
builder = HashChainBuilder(
    node_id="node-1",
    crypto=crypto,
    node_config={"lat": 51.5, "lon": -0.1, "sample_rate": 2_000_000},
    chain_dir="node-1/chain",
    timestamper=TimestampManager(enable_tsa=False, enable_ots=False),
)

# For every detection frame. Returns (entry, batch) only if a stale window closed.
closed = builder.add_detection({"t": 1.0, "range_m": 1200.0, "doppler_hz": -43.5})

# From a periodic timer, so quiet windows still close on the boundary.
closed = builder.close_if_due()

# At shutdown, commit whatever is pending.
entry, batch = builder.close_window()
```

Whenever a call returns a non-`None` `(entry, batch)`, upload both together.
`entry.to_dict()` gives a JSON-ready dict with `None` fields removed.

Archive side:

```python
from retina_custody import HashChainVerifier

keys = {"node-1": crypto.get_public_key_pem()}
verifier = HashChainVerifier(get_public_key=keys.get)

ok, reason = verifier.verify_entry(entry, batch)        # (True, "ok")
ok, issues = verifier.verify_chain([entry], [batch])    # (True, [])
```

Pass `timestamper=TimestampManager()` to enable live DigiCert and OpenTimestamps
requests, or omit it to leave `tsa_token` and `ots_proof` unset.

## Modules

| Module | Contents |
| --- | --- |
| `retina_custody/canonical.py` | `canonicalize()`: the single canonical JSON encoding used for every hash and signature |
| `retina_custody/crypto_backend.py` | `CryptoBackend` ABC, `SoftwareCryptoBackend` (P-256, key persisted with mode 0600), `HardwareCryptoBackend` placeholder |
| `retina_custody/hash_chain.py` | `HashChainBuilder` (node) and `HashChainVerifier` (archive) |
| `retina_custody/tsa_client.py` | `TSAClient`, `OpenTimestampsClient`, `TimestampManager`, RFC 3161 request builder and response check |
| `retina_custody/iq_buffer.py` | `IQCircularBuffer`, `IQCaptureManager` |
| `retina_custody/models.py` | `HashChainEntry`, `IQCapturePackage`, `NodeIdentity` dataclasses |

Public exports from `retina_custody`: `CryptoBackend`, `SoftwareCryptoBackend`,
`HashChainBuilder`, `HashChainVerifier`, `HashChainEntry`, `TimestampManager`,
`canonicalize`.

## Status

- `SoftwareCryptoBackend`, the hash chain, persistence and recovery, the
  verifier, and both timestamp clients are implemented and covered by the test
  suite.
- `HardwareCryptoBackend` is a placeholder. It documents the intended ATECC608B
  behaviour (I2C at 0x6A, on-chip key generation and P-256 signing) and raises
  `NotImplementedError`. It will be filled in when Raspberry Pi nodes are deployed.
- `IQCircularBuffer` and `IQCaptureManager` are implemented but have no caller
  yet, inside or outside this package, and have no tests. They are tracked in
  `vulture_whitelist.py` under UNREVIEWED.
- The live TSA and OpenTimestamps endpoints are not reachable from CI; the
  clients are tested against a local mock HTTP server.

## Development

```bash
pip install -e '.[dev]'
pytest
```

Requires Python 3.10 or newer. Linting and formatting run through pre-commit
(`ruff`, `ruff-format`, and the shared `dead-code` and `ruff-config` hooks from
`offworldlabs/ops`):

```bash
pip install pre-commit==4.6.2 vulture==2.14
pre-commit run --all-files
```

CI runs the same two commands on every pull request and push to `main`.
