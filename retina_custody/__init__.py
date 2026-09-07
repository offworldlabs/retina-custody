"""
RETINA Chain of Custody — Cryptographic integrity for detection data.

Provides:
- CryptoBackend abstraction (hardware ATECC608B / software P-256 stub)
- Windowed hash chain: frames are batched per time window (15 minutes by
  default), the batch is hashed, signed, linked to the previous entry and
  timestamped by third parties. Frames are not individually signed.
- TSA / OpenTimestamps timestamping
- IQ circular buffer with server-triggered capture
"""

from .canonical import canonicalize
from .crypto_backend import CryptoBackend, SoftwareCryptoBackend
from .hash_chain import HashChainBuilder, HashChainVerifier
from .models import HashChainEntry
from .tsa_client import TimestampManager

__all__ = [
    "CryptoBackend",
    "SoftwareCryptoBackend",
    "HashChainBuilder",
    "HashChainVerifier",
    "HashChainEntry",
    "TimestampManager",
    "canonicalize",
]
