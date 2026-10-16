"""Authenticated 64-bit anti-replay window for NLS data sessions.

Call can_accept() before AEAD verification, and mark() only after the AEAD
tag has been verified. Never use accept() on unauthenticated input.
"""
from __future__ import annotations

MAX_SEQUENCE = (1 << 64) - 1
DEFAULT_WINDOW = 128


class ReplayWindow:
    def __init__(self, size: int = DEFAULT_WINDOW):
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 4096:
            raise ValueError("window size must be 1..4096")
        self.size = size
        self.highest = -1
        self.bitmap = 0

    @staticmethod
    def valid_sequence(sequence: int) -> bool:
        return (
            isinstance(sequence, int)
            and not isinstance(sequence, bool)
            and 0 <= sequence <= MAX_SEQUENCE
        )

    def can_accept(self, sequence: int) -> bool:
        if not self.valid_sequence(sequence):
            return False
        if self.highest < 0:
            return True
        if sequence > self.highest:
            return True
        offset = self.highest - sequence
        return offset < self.size and not (self.bitmap & (1 << offset))

    def mark(self, sequence: int) -> bool:
        """Commit a sequence after successful authentication; reject duplicates."""
        if not self.can_accept(sequence):
            return False
        if self.highest < 0:
            self.highest, self.bitmap = sequence, 1
            return True
        if sequence > self.highest:
            shift = sequence - self.highest
            self.bitmap = (
                1 if shift >= self.size
                else ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            )
            self.highest = sequence
            return True
        self.bitmap |= 1 << (self.highest - sequence)
        return True

    def accept(self, sequence: int) -> bool:
        """Compatibility alias. Use only after packet authentication."""
        return self.mark(sequence)
