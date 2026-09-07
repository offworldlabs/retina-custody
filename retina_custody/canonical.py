"""
Canonical JSON serialization.

Every hash and signature in this package is computed over canonical JSON:
sorted keys, no whitespace, ASCII-only. Node and archive must use this exact
serialization or hashes will not match.
"""

from __future__ import annotations

import json
from typing import Any


def canonicalize(data: Any) -> bytes:
    """Produce canonical JSON bytes: sorted keys, no whitespace, ensure_ascii."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
