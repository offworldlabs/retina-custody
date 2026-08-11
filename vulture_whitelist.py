"""Vulture dead-code whitelist.

Read by tools/check-dead-code.sh. Every name here is one vulture reports as
dead but which must not be deleted — or which nobody has decided about yet.
The distinction matters, so the two live in separate sections.

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

# ── UNREVIEWED: appears dead, needs a decision (delete, or finish wiring) ──────
# TODO: no reference found anywhere in the estate
#   retina_custody/crypto_backend.py:154  (unused class)
HardwareCryptoBackend
# TODO: no reference found anywhere in the estate
#   retina_custody/iq_buffer.py:105  (unused class)
IQCaptureManager
# TODO: no reference found anywhere in the estate
#   retina_custody/tsa_client.py:161  (unused class)
TimestampManager
# TODO: no reference found anywhere in the estate
#   retina_custody/iq_buffer.py:126  (unused method)
_.capture
# TODO: no reference found anywhere in the estate
#   retina_custody/iq_buffer.py:188  (unused property)
_.captures
# TODO: no reference found anywhere in the estate
#   retina_custody/hash_chain.py:193  (unused method)
_.get_chain
# TODO: no reference found anywhere in the estate
#   retina_custody/crypto_backend.py:211  (unused method)
_.get_key
# TODO: no reference found anywhere in the estate
#   retina_custody/hash_chain.py:197  (unused method)
_.get_latest_entry
# TODO: model field with no reader found
#   retina_custody/models.py:76  (unused variable)
iq_size_bytes
# TODO: model field with no reader found
#   retina_custody/models.py:18  (unused variable)
public_key_fingerprint
# TODO: model field with no reader found
#   retina_custody/models.py:90  (unused variable)
registered_at
# TODO: no reference found anywhere in the estate
#   retina_custody/packet_signer.py:75  (unused method)
_.sign_data
# TODO: no reference found anywhere in the estate
#   retina_custody/iq_buffer.py:66  (unused method)
_.stop
# TODO: no reference found anywhere in the estate
#   retina_custody/tsa_client.py:172  (unused method)
_.timestamp_entry
