"""Dense append-only allocation with LSB-first bit ordering and permanent revocation."""

from p1qr.status.encoding import MAX_ENTRIES, unsigned_integer
from p1qr.status.errors import StatusCode, StatusError


def read_bit(bitmap: bytes | bytearray, count: int, index: int) -> bool:
    """Return the revoked bit at an assigned ``index``; never read unused padding.

    Index i uses byte i//8 and mask 1<<(i%8). This LSB-first convention matches the
    one-bit IETF TSL packing, not W3C's left-most-bit convention.
    """
    if type(index) is not int or not 0 <= index < count:
        raise StatusError(StatusCode.STATUS_INDEX_OUT_OF_RANGE, "Status index is not assigned.")
    return bool(bitmap[index // 8] & (1 << (index % 8)))


class BitstringStatusList:
    """Mutable issuer bitmap; every position below count is assigned, with no holes.

    A raw bit is never a verifier decision without authenticated binding and snapshot.
    Allocation appends only; revocation is irreversible and idempotent.
    """

    def __init__(self) -> None:
        """Create an empty list with no assigned positions."""
        self._count = 0
        self._bitmap = bytearray()

    @property
    def count(self) -> int:
        """Return the number of allocated positions, excluding final-byte padding."""
        return self._count

    def register(self, index: int | None = None) -> int:
        """Append one position and return its index; reject duplicates, gaps and reuse."""
        if self._count == MAX_ENTRIES:
            raise StatusError(StatusCode.INPUT_TOO_LARGE, "Status list capacity reached.")
        if index is not None and (type(index) is not int or index != self._count):
            raise StatusError(
                StatusCode.INDEX_ALLOCATION_ERROR, "Only the next unused index is allowed."
            )
        assigned = self._count
        if assigned % 8 == 0:
            self._bitmap.append(0)
        self._count += 1
        return assigned

    def revoke(self, index: int) -> None:
        """Set an assigned index to one; repeat calls are safe, absent indexes fail."""
        read_bit(self._bitmap, self._count, index)
        self._bitmap[index // 8] |= 1 << (index % 8)

    def is_revoked(self, index: int) -> bool:
        """Return an assigned entry's bit; this alone is not an authenticated status."""
        return read_bit(self._bitmap, self._count, index)

    def serialize(self) -> bytes:
        """Return an immutable copy of the exact bitmap bytes."""
        return bytes(self._bitmap)

    @classmethod
    def from_bytes(cls, bitmap: bytes, count: int) -> "BitstringStatusList":
        """Validate byte length and zero padding, then return a list of assigned entries.

        This low-level constructor assumes all count positions were allocated; it
        does not invent an issuer registry. Benchmarks explicitly simulate allocation.
        """
        unsigned_integer(count, MAX_ENTRIES)
        if len(bitmap) != (count + 7) // 8:
            raise StatusError(
                StatusCode.MALFORMED_STATUS, "Bitmap length disagrees with assigned count."
            )
        if count % 8 and bitmap[-1] >> (count % 8):
            raise StatusError(StatusCode.MALFORMED_STATUS, "Unassigned padding bits must be zero.")
        result = cls()
        result._count = count
        result._bitmap = bytearray(bitmap)
        return result
