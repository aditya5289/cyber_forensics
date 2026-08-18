"""Tamper-evident audit log (chain of custody).

Lab manual precaution 4: *"Record accurate Case ID, Operator, and Exhibit ID
details to preserve the chain of custody."*

Every state-changing operation in ARGUS appends an entry to a hash-chained
JSON-Lines log.  Each entry embeds the SHA-256 of the previous entry, so
removing or editing any historical line invalidates every line after it.  This
is the same construction used by transparency logs and it means an examiner can
prove — offline, with nothing but the file — that the custody record has not
been rewritten after the fact.

Entry shape::

    {"seq": 3, "ts": "2026-07-29T11:04:02.113Z", "actor": "A.Sharma",
     "action": "acquisition.complete", "detail": {...},
     "prev": "<sha256 of entry 2>", "hash": "<sha256 of this entry>"}
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

GENESIS = "0" * 64


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _canonical(entry: Dict[str, Any]) -> bytes:
    """Serialise deterministically (sorted keys, no spaces) for hashing."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class AuditLog:
    """Append-only hash-chained log backed by a JSONL file."""

    def __init__(self, path: os.PathLike | str, actor: Optional[str] = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.actor = actor or self._default_actor()
        self._seq, self._tip = self._load_tip()

    # ------------------------------------------------------------------ setup
    @staticmethod
    def _default_actor() -> str:
        try:
            return f"{getpass.getuser()}@{socket.gethostname()}"
        except Exception:                                    # pragma: no cover
            return "unknown-operator"

    def _load_tip(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        seq, tip = 0, GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = int(entry.get("seq", seq))
                tip = str(entry.get("hash", tip))
        return seq, tip

    # ------------------------------------------------------------------ write
    def record(self, action: str, detail: Optional[Dict[str, Any]] = None,
               actor: Optional[str] = None) -> Dict[str, Any]:
        """Append one entry and return it."""
        self._seq += 1
        entry: Dict[str, Any] = {
            "seq": self._seq,
            "ts": _now_iso(),
            "actor": actor or self.actor,
            "action": action,
            "detail": detail or {},
            "host": platform.node(),
            "prev": self._tip,
        }
        entry["hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        self._tip = entry["hash"]
        return entry

    # ------------------------------------------------------------------- read
    def entries(self) -> Iterator[Dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        def _gen():
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        yield json.loads(line)
        return _gen()

    def verify(self) -> tuple[bool, List[str]]:
        """Re-walk the chain. Returns ``(ok, problems)``."""
        problems: List[str] = []
        prev = GENESIS
        expected_seq = 1
        for entry in self.entries():
            stated = entry.get("hash")
            body = {k: v for k, v in entry.items() if k != "hash"}
            recomputed = hashlib.sha256(_canonical(body)).hexdigest()
            if stated != recomputed:
                problems.append(
                    f"entry seq={entry.get('seq')} hash mismatch "
                    f"(stated {str(stated)[:12]}…, recomputed {recomputed[:12]}…)")
            if entry.get("prev") != prev:
                problems.append(
                    f"entry seq={entry.get('seq')} breaks the chain "
                    f"(prev={str(entry.get('prev'))[:12]}…, expected {prev[:12]}…)")
            if int(entry.get("seq", -1)) != expected_seq:
                problems.append(
                    f"sequence gap at {expected_seq} (found {entry.get('seq')})")
            prev = stated or prev
            expected_seq = int(entry.get("seq", expected_seq)) + 1
        return (not problems), problems

    @property
    def tip(self) -> str:
        return self._tip

    def __len__(self) -> int:
        return self._seq
