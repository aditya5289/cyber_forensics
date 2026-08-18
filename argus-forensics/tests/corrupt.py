"""Deterministic corruption of valid evidence.

Every test so far has fed ARGUS files built by the same mind that wrote the
parsers, which is circular: the tool passes because the fixtures encode the same
assumptions the code does. Real evidence does not cooperate. It is truncated
mid-write, partially overwritten by later allocations, damaged by a failing
flash controller, or spliced together by a recovery tool that guessed wrong.

So these mutators produce inputs nobody designed for. Two properties must hold
against all of them:

  1. **No crash.** A parser that raises on exhibit 40 of 300 has silently
     removed a device from the examination, and an unhandled traceback in the
     middle of an acquisition is indistinguishable from "this phone was empty".

  2. **No fabrication.** Garbage in must not produce confident-looking records
     out. This is the one that matters. A crash is visible; an invented message
     attributed to a real phone number is not, and it is the kind of thing that
     ends up in a report and then in a courtroom.

Mutations are seeded and deterministic so a failure can be reproduced exactly.
"""
from __future__ import annotations

import hashlib
import random
from typing import Callable, Dict, List, Tuple

Mutator = Callable[[bytes, random.Random], bytes]


def truncate_head(data: bytes, rng: random.Random) -> bytes:
    """Lose the first chunk — what a partial carve off a damaged card gives."""
    if len(data) < 64:
        return data
    return data[rng.randrange(1, max(2, len(data) // 3)):]


def truncate_tail(data: bytes, rng: random.Random) -> bytes:
    """Interrupted copy: the file simply stops."""
    if len(data) < 64:
        return data
    return data[:rng.randrange(len(data) // 3, len(data))]


def bitflips(data: bytes, rng: random.Random) -> bytes:
    """Scattered single-bit errors, as a failing flash cell produces."""
    out = bytearray(data)
    for _ in range(max(1, len(out) // 512)):
        i = rng.randrange(len(out))
        out[i] ^= 1 << rng.randrange(8)
    return bytes(out)


def zero_regions(data: bytes, rng: random.Random) -> bytes:
    """Whole runs zeroed — an erase block that went and took its data with it."""
    out = bytearray(data)
    for _ in range(3):
        if len(out) < 128:
            break
        start = rng.randrange(len(out) - 64)
        out[start:start + rng.randrange(16, 512)] = b"\x00" * min(
            rng.randrange(16, 512), len(out) - start)
    return bytes(out)


def damage_header(data: bytes, rng: random.Random) -> bytes:
    """Corrupt the first 100 bytes without changing the length.

    For SQLite this is the page size, encoding and page count all at once, which
    is precisely the region a reader trusts most.
    """
    out = bytearray(data)
    for i in range(min(100, len(out))):
        if rng.random() < 0.3:
            out[i] = rng.randrange(256)
    return bytes(out)


def splice(data: bytes, rng: random.Random) -> bytes:
    """Two halves of different files joined — what a bad carve produces."""
    if len(data) < 256:
        return data
    cut = rng.randrange(64, len(data) - 64)
    return data[:cut] + data[cut:][::-1]


def random_noise(data: bytes, rng: random.Random) -> bytes:
    """Same size, entirely random. Nothing real can be recovered from this."""
    return bytes(rng.randrange(256) for _ in range(min(len(data), 65536)))


def repeated_byte(data: bytes, rng: random.Random) -> bytes:
    """A single byte repeated.

    0xFF and 0x00 are what unwritten flash and erased regions look like, and
    0xFF in particular decodes to a printable GSM-7 character — the exact trap
    that made the SIM parser emit runs of 'à' as recovered messages.
    """
    return bytes([rng.choice([0x00, 0xFF, 0x41])]) * min(len(data), 65536)


def empty(data: bytes, rng: random.Random) -> bytes:
    return b""


def tiny(data: bytes, rng: random.Random) -> bytes:
    return data[:rng.randrange(1, 16)]


def header_only(data: bytes, rng: random.Random) -> bytes:
    """A valid magic number and nothing behind it.

    The nastiest case for a signature-driven parser: it will confidently claim
    the file.
    """
    return data[:rng.randrange(16, min(120, len(data) or 16) or 16)]


MUTATORS: Dict[str, Mutator] = {
    "truncate_head": truncate_head,
    "truncate_tail": truncate_tail,
    "bitflips": bitflips,
    "zero_regions": zero_regions,
    "damage_header": damage_header,
    "splice": splice,
    "random_noise": random_noise,
    "repeated_byte": repeated_byte,
    "empty": empty,
    "tiny": tiny,
    "header_only": header_only,
}


def mutate(data: bytes, name: str, seed: int) -> bytes:
    return MUTATORS[name](data, random.Random(seed))


def variants(data: bytes, seeds: Tuple[int, ...] = (1, 2, 3)
             ) -> List[Tuple[str, int, bytes]]:
    """Every mutator at every seed. Deterministic, so failures reproduce."""
    out: List[Tuple[str, int, bytes]] = []
    for name in sorted(MUTATORS):
        for seed in seeds:
            out.append((name, seed, mutate(data, name, seed)))
    return out


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]
