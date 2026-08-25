# Copyright (C) 2026 quip.network
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The one exception type every profile extension raises.

Defined in Python rather than in Rust on purpose. The wheel ships one compiled
extension per profile, and six extensions each declaring their own exception
class would give six unrelated classes: ``except HashSigsError`` caught from
one profile would not catch an error raised by another. Every extension imports
this class at module init instead, so there is exactly one of it per
interpreter no matter how many profiles a caller touches.
"""

__all__ = ["HashSigsError", "ERROR_CODES"]


class HashSigsError(Exception):
    """A signing or key-handling operation failed.

    Carries a stable machine-readable :attr:`code` alongside the human-readable
    message. Branch on the code, never on the message text.

    Messages never echo the input that caused them, because that input is
    routinely secret key material and messages routinely reach logs.
    """

    #: One of :data:`ERROR_CODES`. Set by the extension when it raises.
    code: str = "ERR_UNKNOWN"

    def __str__(self) -> str:
        base = super().__str__()
        return f"[{self.code}] {base}" if self.code else base


#: Every code an extension can attach to :class:`HashSigsError`.
#:
#: Kept in step with ``ErrorCode`` in the Rust crate by
#: ``test_errors.py::test_error_codes_match_the_rust_enum``, which reads the
#: variants out of the source rather than trusting this copy.
ERROR_CODES = (
    "ERR_BAD_LENGTH",
    "ERR_STATEFUL_LEAVES_EXHAUSTED",
    "ERR_SIGNING_FAILED",
    "ERR_KEYGEN_FAILED",
    "ERR_INVALID_INPUT",
    "ERR_IMPORT_INVALID",
    "ERR_ENVELOPE_MALFORMED",
)
