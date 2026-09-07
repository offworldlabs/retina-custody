"""
Data models for chain of custody system.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class HashChainEntry:
    """One link in the hash chain, covering one time window of detections."""

    node_id: str
    window_start: str  # ISO 8601 UTC, inclusive, e.g. "2026-03-19T14:00:00Z"
    window_end: str  # ISO 8601 UTC, exclusive, e.g. "2026-03-19T14:15:00Z"
    prev_hash: str  # SHA-256 of the previous entry (or "genesis" for first)
    detections_hash: str  # SHA-256 of the canonical JSON array of this window's frames
    n_detections: int
    node_config_hash: str  # SHA-256 of node config at window close
    firmware_version: str
    timestamp_utc: str  # ISO 8601 creation timestamp
    entry_hash: str  # SHA-256 of canonical JSON of this entry (excluding signature fields)
    signature: str  # hex-encoded ECDSA signature over the canonical JSON of the hashed fields
    signing_mode: str  # "hardware" or "software"
    tsa_token: str | None = None  # base64-encoded RFC 3161 TSA response
    ots_proof: str | None = None  # base64-encoded OpenTimestamps proof

    def to_dict(self) -> dict:
        d = asdict(self)
        # Remove None optional fields
        return {k: v for k, v in d.items() if v is not None}

    @staticmethod
    def from_dict(d: dict) -> HashChainEntry:
        return HashChainEntry(**{k: v for k, v in d.items() if k in HashChainEntry.__dataclass_fields__})


@dataclass
class IQCapturePackage:
    """Metadata for a captured IQ sample package."""

    node_id: str
    capture_id: str
    window_start_ms: int
    window_end_ms: int
    iq_hash: str  # SHA-256 of raw IQ data
    signature: str  # ECDSA signature of iq_hash
    signing_mode: str
    tsa_token: str | None = None
    node_config_hash: str = ""
    trigger_reason: str = ""  # e.g. "anomalous_detection"
    iq_size_bytes: int = 0

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class NodeIdentity:
    """Public identity of a registered node."""

    node_id: str
    public_key_pem: str  # PEM-encoded P-256 public key
    public_key_fingerprint: str  # first 16 hex chars of SHA-256(DER public key)
    serial_number: str  # hardware serial (ATECC608B) or generated UUID
    signing_mode: str  # "hardware" or "software"
    registered_at: str = ""  # ISO 8601

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> NodeIdentity:
        return NodeIdentity(**{k: v for k, v in d.items() if k in NodeIdentity.__dataclass_fields__})
