"""ULID generation (lexicographically sortable, time-ordered IDs).

Used for approval_id and audit_id. A minimal implementation (Crockford base32,
48-bit millisecond timestamp + 80 bits of randomness) — avoids a third-party
dependency. Not strictly monotonic within a millisecond, which is fine here.
"""

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    timestamp_ms = int(time.time() * 1000)
    randomness = int.from_bytes(os.urandom(10), "big")
    value = (timestamp_ms << 80) | randomness
    chars = [""] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return "".join(chars)
