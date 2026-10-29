"""Vulture dead-code whitelist.

Read by tools/check-dead-code.sh. Every name here is one vulture reports as
dead but which must not be deleted, or which nobody has decided about yet.
The distinction matters, so each kind lives in its own section.

BENCHED holds code that is unused by decision: a feature parked for planned
revival, with a pointer to the doc that records why.

Add to CONTRACTS only when the name is genuinely referenced by something
vulture cannot see: a framework calling in, a wire format, a config key. Real
dead code should be deleted, not whitelisted.

The UNREVIEWED section is a backlog, not an exemption. Each entry is code that
appears genuinely unreachable and needs a decision — delete it, or wire up
whatever was left unfinished. The gate is green with these listed so that it
starts catching NEW dead code immediately; working through them is separate.
"""
# ruff: noqa: B018, F821
# B018 — bare-name expressions are how vulture whitelists work.
# F821 — these names are defined in other modules; only vulture reads this file.

_ = type("_", (), {})()

# ── Contracts: referenced by something vulture cannot see ─────────────────────
# (none)

# ── Benched: unused on purpose, kept for planned revival ──────────────────────
# IQ capture is benched pending a later revival (docs/iq-capture.md). Delete these
# entries when it is wired up again or when the decision changes.
#   retina_custody/iq_buffer.py  (unused class, method, property)
IQCaptureManager
_.capture
_.captures
_.stop
#   retina_custody/models.py  (IQCapturePackage field with no reader)
iq_size_bytes

# ── UNREVIEWED: appears dead, needs a decision (delete, or finish wiring) ──────
# TODO: no reference found anywhere in the estate
#   retina_custody/crypto_backend.py:152  (unused class)
HardwareCryptoBackend
# TODO: model field with no reader found
#   retina_custody/models.py:65  (unused variable)
public_key_fingerprint
# TODO: model field with no reader found
#   retina_custody/models.py:68  (unused variable)
registered_at
