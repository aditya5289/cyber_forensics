#!/usr/bin/env python3
"""ARGUS Forensics — application entry point.

This is what the double-click launchers run. It exists to make the failure
modes friendly: a forensic examiner double-clicking an icon should not be
shown a Python traceback, and should not be left guessing why nothing opened.

So before starting anything it checks the Python version, confirms the package
is importable, reports which optional features are available, and — if
something is fatally wrong — prints a plain-language explanation and keeps the
console window open long enough to read it.

Usage::

    python argus_app.py                     # start the workbench
    python argus_app.py --workspace D:\\Cases
    python argus_app.py --port 9000 --no-browser
    python argus_app.py --check              # environment report, then exit
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path

MIN_PYTHON = (3, 10)
HERE = Path(__file__).resolve().parent


# --------------------------------------------------------------------------
def _box(title: str, lines: list[str], width: int = 72) -> str:
    out = ["", "  " + "─" * width, f"  {title}", "  " + "─" * width]
    for line in lines:
        for wrapped in (textwrap.wrap(line, width - 2) or [""]):
            out.append("  " + wrapped)
    out += ["  " + "─" * width, ""]
    return "\n".join(out)


def _hold(exit_code: int) -> None:
    """Keep a double-clicked console window open so the message is readable."""
    if os.name == "nt" and sys.stdin and sys.stdin.isatty():
        try:
            input("  Press Enter to close this window… ")
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(exit_code)


def preflight() -> dict:
    """Check the environment. Returns a report; exits on a fatal problem."""
    if sys.version_info < MIN_PYTHON:
        print(_box("ARGUS cannot start", [
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required.",
            f"This interpreter is Python "
            f"{sys.version_info.major}.{sys.version_info.minor}"
            f".{sys.version_info.micro}.",
            "",
            "Install a current Python from https://www.python.org/downloads/ "
            "and make sure to tick 'Add Python to PATH' during installation.",
        ]))
        _hold(2)

    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))

    try:
        import argus                                          # noqa: F401
        from argus.server.workbench import _feature_report
        from argus.devices.detect import toolchain_status
    except ImportError as exc:
        print(_box("ARGUS cannot start", [
            f"The argus package could not be imported: {exc}",
            "",
            f"This script expects to live alongside the 'argus' folder. It is "
            f"currently running from:",
            f"  {HERE}",
            "",
            "If you moved the launcher, move it back — or install the package "
            "with:  pip install -e .",
        ]))
        _hold(3)

    return {
        "version": argus.__version__,
        "python": sys.version.split()[0],
        "features": _feature_report(),
        "toolchain": toolchain_status(),
    }


def print_report(report: dict) -> None:
    features = report["features"]
    tools = report["toolchain"]
    lines = [
        f"ARGUS {report['version']}   ·   Python {report['python']}",
        "",
        "Acquisition toolchains:",
    ]
    lines.append(
        f"  adb                {'found' if tools['adb']['available'] else 'not installed'}"
        + ("" if tools["adb"]["available"]
           else f"   ({tools['adb']['install_hint']})"))
    lines.append(
        f"  libimobiledevice   {'found' if tools['libimobiledevice']['available'] else 'not installed'}"
        + ("" if tools["libimobiledevice"]["available"]
           else f"   ({tools['libimobiledevice']['install_hint']})"))
    lines += ["", "Optional features:"]
    for key, info in features.items():
        state = "available" if info["available"] else "not installed"
        lines.append(f"  {key:18s} {state}"
                     + ("" if info["available"] else f"   ({info['install']})"))
    missing = [k for k, v in features.items() if not v["available"]]
    if missing:
        lines += ["",
                  "ARGUS runs without these. They only affect EXIF/GPS "
                  "extraction and the Excel, Word and PDF report formats — "
                  "HTML, XML, JSON and CSV always work."]
    print(_box("Environment", lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="argus_app",
        description="Start the ARGUS Forensics workbench application.")
    parser.add_argument("--workspace", default=None,
                        help="where cases and reports are kept "
                             "(default: ~/ARGUS)")
    parser.add_argument("--port", type=int, default=8742)
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser window automatically")
    parser.add_argument("--check", action="store_true",
                        help="print an environment report and exit")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--token", default=None,
                        help="session token (generated if omitted; used by desktop shell)")
    parser.add_argument("--ready-json", action="store_true",
                        help="print one JSON line when the server is ready (desktop shell)")
    args = parser.parse_args(argv)

    report = preflight()
    if args.check:
        print_report(report)
        _hold(0)

    workspace = Path(args.workspace).expanduser() if args.workspace \
        else Path.home() / "ARGUS"

    from argus.server.workbench import serve
    try:
        serve(workspace=workspace, port=args.port,
              open_browser=not args.no_browser, quiet=args.quiet,
              token=args.token, ready_json=args.ready_json)
    except OSError as exc:
        print(_box("ARGUS could not start its local service", [
            str(exc),
            "",
            f"Port {args.port} may be in use by another program. Try:",
            f"  python argus_app.py --port {args.port + 1}",
        ]))
        _hold(4)
    except Exception as exc:                                  # pragma: no cover
        print(_box("ARGUS stopped unexpectedly", [
            f"{type(exc).__name__}: {exc}",
            "",
            "If this repeats, run  python argus_app.py --check  and include "
            "the output when reporting the problem.",
        ]))
        _hold(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
