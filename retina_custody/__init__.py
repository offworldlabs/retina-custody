"""
RETINA Chain of Custody — Cryptographic integrity for detection data.

Provides:
- CryptoBackend abstraction (hardware ATECC608B / software P-256 stub)
- Detection packet signing & verification
- Hourly hash chain construction
- TSA / OpenTimestamps timestamping
- IQ circular buffer with server-triggered capture
"""

from .crypto_backend import CryptoBackend, SoftwareCryptoBackend
from .hash_chain import HashChainBuilder
from .models import HashChainEntry, SignedPacket
from .packet_signer import PacketSigner

__all__ = [
    "CryptoBackend",
    "SoftwareCryptoBackend",
    "PacketSigner",
    "HashChainBuilder",
    "SignedPacket",
    "HashChainEntry",
]
