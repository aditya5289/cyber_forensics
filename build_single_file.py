#!/usr/bin/env python3
"""Fuse ARGUS.ps1 into one double-clickable .bat file.

The tool needed two files side by side, and that has been the single most
reliable way to break it: the launcher next to the wrong copy of the script,
or the script alone with no way to start it, or - repeatedly - an old copy
launched by mistake. One file cannot drift out of step with itself.

The result is a batch/PowerShell polyglot. cmd.exe reads the top, which asks
PowerShell to copy everything after a marker into a temp script and run it,
then stops at `exit /b` and never sees the PowerShell below. Windows treats it
as an ordinary .bat, so it runs on a double-click with nothing installed.

Two details that matter:

  - The marker is written in two halves in the extractor (`'...SCRIPT' + '_BEGIN...'`)
    so the literal string appears exactly once in the file. Otherwise IndexOf
    finds the extractor's own copy and slices in the wrong place.
  - CRLF throughout. cmd.exe is unreliable on LF-only batch files, and the
    failure is silent and bizarre rather than a clean error.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

MARKER = '#___ARGUS_SCRIPT_BEGIN___'

STUB = r"""@echo off
rem ===========================================================================
rem  ARGUS Field Tool - single-file edition.
rem
rem  Double-click this file. Nothing is installed, nothing leaves the machine,
rem  no network is used, no admin rights are needed.
rem
rem  This one file contains the whole tool. cmd.exe reads the few lines below;
rem  everything after the marker is PowerShell, which cmd never reaches.
rem
rem  -ExecutionPolicy Bypass applies to THIS process only. It does not change
rem  the machine's policy - which matters on a managed forensic workstation,
rem  where altering it would be both noticed and reverted.
rem
rem  -STA is required: the file and folder dialogs are single-threaded COM.
rem ===========================================================================

setlocal
set "ARGUS_SELF=%~f0"
set "ARGUS_TMP=%TEMP%\ARGUS-%RANDOM%%RANDOM%.ps1"

where powershell >nul 2>&1
if errorlevel 1 (
    echo.
    echo   Windows PowerShell was not found on the PATH.
    echo   ARGUS needs it, and it ships with every supported version of Windows,
    echo   so this usually means PATH has been altered rather than that it is
    echo   missing. Try: %%SystemRoot%%\System32\WindowsPowerShell\v1.0\powershell.exe
    echo.
    pause
    exit /b 9
)

rem  Deliberately one long line. Caret continuation inside a quoted -Command
rem  string is parsed inconsistently across cmd versions and fails in ways that
rem  look like the script is corrupt. 330 characters is nowhere near the 8191
rem  limit, so there is nothing to gain by splitting it.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $t=[IO.File]::ReadAllText($env:ARGUS_SELF); $m='#___ARGUS_SCRIPT'+'_BEGIN___'; $i=$t.IndexOf($m); if ($i -lt 0) { exit 2 }; [IO.File]::WriteAllText($env:ARGUS_TMP, $t.Substring($i+$m.Length), (New-Object Text.UTF8Encoding $false)); exit 0 } catch { exit 3 }"

if errorlevel 3 (
    echo.
    echo   Could not write the temporary script to:
    echo     %ARGUS_TMP%
    echo.
    echo   On a locked-down workstation this is usually AppLocker or a policy
    echo   blocking script files in the temp folder. Ask for ARGUS.ps1 as a
    echo   plain script instead - it does exactly the same thing.
    echo.
    pause
    exit /b 3
)
if errorlevel 2 (
    echo.
    echo   This file appears to be truncated or corrupted - the embedded script
    echo   marker is missing. Download it again and check the size.
    echo.
    pause
    exit /b 2
)

rem  ---------------------------------------------------------------------
rem  Pre-flight: parse the script with PowerShell's OWN parser before running
rem  it.
rem
rem  A syntax error anywhere in a 3,600-line file stops the whole thing
rem  loading, and the raw output is a wall of red that says nothing about what
rem  to do. This runs the authoritative parser first and, if it objects, prints
rem  each problem with its line, column and the offending source - then stops,
rem  because a file that will not parse cannot be run and pretending otherwise
rem  only buries the message further up the scrollback.
rem  ---------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "$e=$null; $t=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:ARGUS_TMP,[ref]$t,[ref]$e); if ($e -and $e.Count -gt 0) { $src=[IO.File]::ReadAllLines($env:ARGUS_TMP); Write-Host ''; Write-Host ('  SYNTAX ERRORS: {0}' -f $e.Count) -ForegroundColor Red; Write-Host '  This build will not run. Nothing was executed.' -ForegroundColor Red; Write-Host ''; foreach ($x in ($e | Select-Object -First 12)) { $ln=$x.Extent.StartLineNumber; Write-Host ('  line {0}, col {1}' -f $ln,$x.Extent.StartColumnNumber) -ForegroundColor Yellow; Write-Host ('    {0}' -f $x.Message) -ForegroundColor Yellow; if ($ln -ge 1 -and $ln -le $src.Count) { Write-Host ('    | {0}' -f $src[$ln-1].Trim()) -ForegroundColor DarkGray }; Write-Host '' }; exit 4 }"

if errorlevel 4 (
    echo.
    echo   Report the block above - it names every problem, with line numbers.
    echo.
    pause
    exit /b 4
)

powershell -NoProfile -ExecutionPolicy Bypass -STA -File "%ARGUS_TMP%" %*
set "ARGUS_RC=%ERRORLEVEL%"

del "%ARGUS_TMP%" >nul 2>&1

if not "%ARGUS_RC%"=="0" (
    echo.
    echo   ARGUS exited with code %ARGUS_RC%. The reason is above.
    echo.
    pause
)
endlocal & exit /b %ARGUS_RC%

"""


def main() -> int:
    here = Path(__file__).parent
    source = here / 'ARGUS.ps1'
    target = here / 'ARGUS.bat'

    if not source.exists():
        print(f"ERROR: {source} not found")
        return 1

    script = source.read_text(encoding='utf-8')

    non_ascii = [(i, ch) for i, ch in enumerate(script) if ord(ch) > 127]
    if non_ascii:
        i, ch = non_ascii[0]
        print(f"ERROR: script contains non-ASCII U+{ord(ch):04X} at offset {i}.")
        print("       A polyglot must be single-byte throughout or cmd mis-parses it.")
        return 1

    if MARKER in script:
        print("ERROR: the marker already appears inside the script itself.")
        return 1

    # CRLF for the WHOLE file, stub included. The first version of this line
    # converted only the script and left the stub on LF, which is precisely the
    # failure the docstring above warns about - cmd.exe mis-parses LF-only
    # batch files silently. Caught by the stub check, not by reading it back.
    def crlf(s: str) -> str:
        return s.replace('\r\n', '\n').replace('\n', '\r\n')

    body = crlf(STUB) + MARKER + '\r\n' + crlf(script)
    target.write_text(body, encoding='ascii', newline='')

    raw = target.read_bytes()
    print(f"Wrote {target.name}")
    print(f"  size        : {len(raw):,} bytes")
    print(f"  sha256      : {hashlib.sha256(raw).hexdigest()}")
    print(f"  marker count: {raw.count(MARKER.encode())}  (must be 1)")
    print()

    # ---- verify the extraction the stub will perform ---------------------
    text = raw.decode('ascii')
    idx = text.index(MARKER)
    extracted = text[idx + len(MARKER):]
    recovered = extracted.lstrip('\r\n')

    original = script.replace('\r\n', '\n')
    recovered_lf = recovered.replace('\r\n', '\n')

    ok = recovered_lf == original
    print("Extraction check (mirrors exactly what the stub does):")
    print(f"  recovered {len(recovered_lf):,} chars vs original {len(original):,}")
    print(f"  byte-identical after extraction: {ok}")
    if not ok:
        for n, (a, b) in enumerate(zip(recovered_lf, original)):
            if a != b:
                print(f"  first difference at char {n}: {a!r} vs {b!r}")
                break
        return 1

    stub_lines = STUB.count('\n')
    print(f"  cmd.exe parses {stub_lines} lines then stops at 'exit /b'")
    print(f"  PowerShell section starts at byte {idx + len(MARKER) + 2:,}")
    print()
    print("RESULT: single file builds and round-trips cleanly.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
