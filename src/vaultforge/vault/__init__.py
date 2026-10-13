"""Encrypted vault internals (format v1).

This subpackage is the implementation behind the future ``vaultforge vault``
commands. It is split so each concern can be reviewed and tested on its own:

* :mod:`vaultforge.vault.errors` -- the exception hierarchy.
* :mod:`vaultforge.vault.crypto` -- Argon2id and ChaCha20-Poly1305 primitives.
* :mod:`vaultforge.vault.format` -- the on-disk v1 container layout.
* :mod:`vaultforge.vault.payload` -- canonical JSON payload serialization.

The byte-level format is specified in ``docs/VAULT_FORMAT.md`` and the design and
threat model in ``docs/VAULT_DESIGN.md``. Nothing in this package writes to the
standard streams, logs, or uses the ``random`` module.
"""

from __future__ import annotations
