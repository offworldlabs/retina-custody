# IQ capture commitments (benched)

**Status:** benched on 2026-10-29. It is planned to come back, with no date set.

The code stays in the package (`retina_custody/iq_buffer.py`, `IQCapturePackage` in
`retina_custody/models.py`), but it is not supported and nothing should call it. Leaving it
in place costs nothing, because none of it runs unless something calls it. This doc records
what the feature is for, what exists, and what has to change before it can ship.

## What it is for

A detection is only as trustworthy as the signal it came from. IQ capture lets the archive
ask a node for the raw IQ samples behind a stretch of detections, while giving proof that
the node committed to those exact bytes at a known time *before* it uploaded them. A node
cannot then swap in different samples after seeing what the archive is interested in.

## Protocol as built

1. The node keeps the last 120 s of IQ in an in-RAM ring buffer (`IQCircularBuffer`).
   Nothing goes to disk.
2. On request, `IQCaptureManager.capture(window_start_ms, window_end_ms)` freezes the
   matching chunks, hashes them, signs them, and requests an RFC 3161 timestamp for the hash.
3. It returns an `IQCapturePackage` (the commitment) and the raw bytes.
4. The caller sends the commitment, waits for the server to acknowledge it, and only then
   uploads the IQ bytes.

## What already exists

| Side | What | State |
| --- | --- | --- |
| Node | `IQCircularBuffer`, `IQCaptureManager`, `IQCapturePackage` | Implemented, never called, no tests. Synthetic data source only (1 KiB random chunks per second). |
| Server | `POST /api/custody/iq-commitment` on retina-server | Live and deliberately left in place for revival. Stores the request (`node_id`, `capture_id`, any other fields) in server state, last 200 per node, with only the shared API key checked. No signature check and no IQ upload endpoint. |

## What must change before revival

These are design problems, not polish. Revival should treat the current code as a reference
for the protocol and expect to rewrite most of it.

- **Sign the digest, not the bytes.** `capture()` calls `crypto.sign_hex(iq_data)` on the
  raw samples. The ATECC608B signs a 32-byte digest only, so this cannot work on hardware
  nodes. (The `IQCapturePackage.signature` comment already says "signature of iq_hash",
  which is what it should be.)
- **Fit the buffer to the node.** The module's own sizing note puts 2 minutes of real IQ at
  2 MHz at about 960 MB, far more RAM than a Pi has. Decide sample rate, channels and window
  length from what the node can hold, or buffer somewhere other than RAM.
- **Link captures to the hash chain.** A capture stands alone today. Nothing in a chain
  entry references it, so the archive cannot tie IQ to the detections it supports.
- **Use both timestamp services.** `IQCaptureManager` uses `TSAClient` directly and gets no
  OpenTimestamps proof, unlike chain entries, which use `TimestampManager`.
- **Enforce commit before upload.** The ordering is only a docstring. Something has to
  enforce it, either the server refusing IQ with no prior commitment or a node-side state
  machine.
- **Real data source and tests.** Feed the buffer from the SDR pipeline and test the module.
- **Server verification.** The endpoint must verify the signature against the node's key,
  as the chain-entry endpoint does, and there is no IQ upload or storage path yet.

## Keeping the door open meanwhile

Work done before revival should not close off IQ:

- The hardware backend (PLAN iteration 5) must expose signing of an external digest. It
  needs this for chain entries anyway.
- Entry schema v2 (PLAN iteration 8) should leave room for an entry to reference other
  signed artifacts, such as a capture, even though it will not use that yet.
