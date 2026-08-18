"""Measure ARGUS against evidence-sized inputs.

Peak resident memory is the number that decides whether a tool is usable. An
examiner's workstation has 16 or 32 GB and the image on the bench is routinely
larger than that, so any component whose memory grows with the size of the
evidence is unusable no matter how fast it is. This measures growth, not just
throughput.

Run:  python3 tools/bench.py [--size-mb 256]
"""
from __future__ import annotations

import argparse
import os
import pathlib
import resource
import sqlite3
import sys
import tempfile
import time
from typing import Callable, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def peak_rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes, macOS bytes.
    return usage / 1024 if sys.platform != "darwin" else usage / (1024 * 1024)


def timed(label: str, fn: Callable[[], object]) -> Tuple[object, float, float]:
    before = peak_rss_mb()
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    after = peak_rss_mb()
    print(f"  {label:<38} {elapsed:7.2f}s   peak RSS {after:8.1f} MB "
          f"(+{max(after - before, 0):.1f})")
    return result, elapsed, after


def make_large_db(path: str, target_mb: int) -> str:
    """A messaging database of roughly the requested size."""
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, "
                "date INTEGER, body TEXT, type INTEGER, payload BLOB)")
    filler = b"\x00" * 900
    rows, batch = 0, []
    target_bytes = target_mb * 1024 * 1024
    while os.path.getsize(path) < target_bytes:
        for _ in range(2000):
            rows += 1
            batch.append((f"+4477009{rows % 100000:05d}",
                          1700000000000 + rows * 1000,
                          f"Message {rows} about the delivery schedule",
                          rows % 2, filler))
        con.executemany("INSERT INTO sms (address,date,body,type,payload) "
                        "VALUES (?,?,?,?,?)", batch)
        con.commit()
        batch.clear()
    con.close()
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--size-mb", type=int, default=256)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    workdir = tempfile.mkdtemp(prefix="argus-bench-")
    db_path = os.path.join(workdir, "mmssms.db")

    print(f"\nBuilding a ~{args.size_mb} MB database…")
    make_large_db(db_path, args.size_mb)
    actual = os.path.getsize(db_path) / (1024 * 1024)
    print(f"  {actual:.0f} MB at {db_path}")

    from argus.parsers.sqlite_reader import ForensicSQLite

    print(f"\nReading a {actual:.0f} MB database")
    print(f"  {'baseline':<38} {'':>7}    peak RSS {peak_rss_mb():8.1f} MB")

    def open_and_header():
        with ForensicSQLite(db_path) as db:
            return db.page_count, db.page_size

    (pages, page_size), _, rss_open = timed("open + parse header", open_and_header)
    print(f"     ({pages} pages of {page_size} bytes)")

    def read_pages():
        with ForensicSQLite(db_path) as db:
            total = 0
            for n in range(1, min(db.page_count, 20000) + 1):
                total += len(db.page(n))
            return total

    read, _, rss_pages = timed("random page access (20k pages)", read_pages)

    ratio = rss_pages / actual if actual else 0
    print(f"\n  Peak RSS / evidence size: {ratio:.3f}")
    if ratio > 0.5:
        print("  FAIL — memory is growing with the size of the evidence.")
        verdict = 1
    else:
        print("  PASS — memory is decoupled from the size of the evidence.")
        verdict = 0

    if not args.keep:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
