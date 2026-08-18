#!/usr/bin/env python3
"""Static check of a PowerShell script for the errors that stop it loading.

Not a PowerShell parser. It is a scanner for the specific failures that make a
long script fail *at parse time*, before a single line runs - because those are
the ones that waste an afternoon:

  - unbalanced { } ( ) [ ]
  - a here-string that is never terminated, or whose terminator is indented
  - an unclosed quote
  - a function that is called but never defined

The reason for writing this rather than trusting a read-through is that a
single missing brace in a 2,400-line file produces one error message pointing
at the last line of the file, and no indication of where the imbalance began.
This reports the position where the depth went wrong.
"""
from __future__ import annotations

import re
import sys
from collections import Counter

PAIRS = {'{': '}', '(': ')', '[': ']'}
CLOSERS = {v: k for k, v in PAIRS.items()}


def scan(text: str):
    lines = text.split('\n')
    stack = []            # (char, line_no, col)
    errors = []
    i = 0
    line_no = 1
    col = 1
    n = len(text)

    in_block_comment = False
    here_string = None    # (terminator, start_line)

    while i < n:
        ch = text[i]

        if ch == '\n':
            line_no += 1
            col = 1
            i += 1
            continue

        # --- here-strings ------------------------------------------------
        # The terminator must sit at the very start of a line. An indented
        # "@ is the classic cause of "string is missing the terminator",
        # and the reported line is nowhere near the real one.
        if here_string is not None:
            term = here_string[0]
            if col == 1 and text[i:i + 2] == term:
                i += 2
                col += 2
                here_string = None
                continue
            i += 1
            col += 1
            continue

        if in_block_comment:
            if text[i:i + 2] == '#>':
                in_block_comment = False
                i += 2
                col += 2
                continue
            i += 1
            col += 1
            continue

        if text[i:i + 2] == '<#':
            in_block_comment = True
            i += 2
            col += 2
            continue

        if text[i:i + 2] in ('@"', "@'"):
            # Only a here-string if the rest of the line is blank.
            eol = text.find('\n', i)
            rest = text[i + 2:eol if eol != -1 else n]
            if rest.strip() == '':
                here_string = ('"@' if text[i + 1] == '"' else "'@", line_no)
                i = (eol if eol != -1 else n)
                continue

        if ch == '#':
            eol = text.find('\n', i)
            i = eol if eol != -1 else n
            continue

        # --- quoted strings ----------------------------------------------
        if ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                if text[j] == '\n':
                    errors.append((line_no, "single-quoted string not closed on its line"))
                    break
                j += 1
            else:
                errors.append((line_no, "single-quoted string never closed"))
            consumed = text[i:j + 1]
            line_no += consumed.count('\n')
            i = j + 1
            col = 1 if '\n' in consumed else col + len(consumed)
            continue

        if ch == '"':
            j = i + 1
            depth = 0
            while j < n:
                c = text[j]
                if c == '`':
                    j += 2
                    continue
                if c == '$' and j + 1 < n and text[j + 1] == '(':
                    depth += 1
                    j += 2
                    continue
                if depth > 0:
                    if c == '(':
                        depth += 1
                    elif c == ')':
                        depth -= 1
                    j += 1
                    continue
                if c == '"':
                    break
                if c == '\n':
                    errors.append((line_no, "double-quoted string not closed on its line"))
                    break
                j += 1
            else:
                errors.append((line_no, "double-quoted string never closed"))
            consumed = text[i:j + 1]
            line_no += consumed.count('\n')
            i = j + 1
            col = 1 if '\n' in consumed else col + len(consumed)
            continue

        # --- brackets ------------------------------------------------------
        if ch in PAIRS:
            stack.append((ch, line_no, col))
        elif ch in CLOSERS:
            if not stack:
                errors.append((line_no, f"closing '{ch}' with nothing open"))
            else:
                open_ch, open_line, open_col = stack.pop()
                if PAIRS[open_ch] != ch:
                    errors.append((
                        line_no,
                        f"'{ch}' closes '{open_ch}' opened at line {open_line} col {open_col}"))

        i += 1
        col += 1

    if here_string is not None:
        errors.append((here_string[1], f"here-string opened here is never terminated "
                                       f"(needs {here_string[0]} at column 1)"))

    for open_ch, open_line, open_col in stack:
        errors.append((open_line, f"'{open_ch}' opened at col {open_col} is never closed"))

    return errors, lines


SCOPES = {'env', 'script', 'global', 'local', 'private', 'using', 'variable',
          'function', 'workflow', 'alias', 'hklm', 'hkcu', 'cert', 'wsman'}


def check_variable_colons(text: str):
    """Find "$name:" inside double-quoted strings.

    PowerShell reads "$n:" as a drive-qualified variable - the same syntax that
    makes "$env:PATH" work - so it demands a real drive name after the $ and
    refuses to parse anything else. The fix is "${n}:".

    This is worth a dedicated rule because it is invisible to a brace-and-quote
    check: the file is perfectly balanced and still will not load. It shipped
    once, in a string that only ran when a custody chain was verified, so no
    amount of reading the happy path would have caught it either.
    """
    hits = []
    for n, line in enumerate(text.split('\n'), 1):
        if line.lstrip().startswith('#'):
            continue
        for m in re.finditer(r'\$([A-Za-z_]\w*):', line):
            if m.group(1).lower() in SCOPES:
                continue
            # Only a problem inside a double-quoted string.
            if line[:m.start()].count('"') % 2 == 1:
                hits.append((n, m.group(1), line.strip()))
    return hits


def check_functions(text: str):
    """Every function called should exist, allowing for cmdlets and methods."""
    defined = set(m.group(1).lower() for m in
                  re.finditer(r'(?im)^\s*function\s+([A-Za-z][\w-]*)', text))
    called = Counter()
    for m in re.finditer(r'(?m)(?:^|[\s\|\(\{;])([A-Z][a-z]+-[A-Za-z]\w*)', text):
        called[m.group(1).lower()] += 1

    known_cmdlets = {
        'get-childitem', 'get-content', 'set-content', 'add-content', 'get-item',
        'new-item', 'remove-item', 'test-path', 'resolve-path', 'join-path',
        'split-path', 'get-filehash', 'export-csv', 'convertto-json',
        'convertfrom-json', 'write-host', 'read-host', 'get-date', 'get-command',
        'get-pnpdevice', 'get-ciminstance', 'get-psdrive', 'get-service',
        'measure-object', 'sort-object', 'select-object', 'where-object',
        'foreach-object', 'group-object', 'out-null', 'out-string',
        'get-itemproperty', 'push-location', 'pop-location', 'start-sleep',
        'invoke-expression', 'add-type', 'new-object', 'set-variable',
        'get-variable', 'out-file', 'compare-object', 'select-string',
        'get-process', 'stop-process', 'test-connection', 'get-random',
        'write-output', 'write-error', 'write-warning', 'write-verbose',
        'get-location', 'set-location', 'copy-item', 'move-item', 'rename-item',
        'get-member', 'format-table', 'format-list', 'import-csv',
        'get-pnpdeviceproperty', 'add-member', 'new-timespan', 'start-process',
        'get-filehash', 'convertto-securestring', 'get-eventlog',
    }
    missing = {}
    for name, count in called.items():
        if name in defined or name in known_cmdlets:
            continue
        missing[name] = count
    return defined, missing


def main(path: str) -> int:
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        text = fh.read()

    errors, lines = scan(text)
    defined, missing = check_functions(text)
    colon_hits = check_variable_colons(text)

    print(f"File      : {path}")
    print(f"Lines     : {len(lines):,}")
    print(f"Functions : {len(defined)} defined")
    print()

    if errors:
        print(f"STRUCTURAL ERRORS ({len(errors)}):")
        for line_no, msg in sorted(errors)[:40]:
            src = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ''
            print(f"  line {line_no:>5}: {msg}")
            if src:
                print(f"              | {src[:100]}")
        print()
    else:
        print("STRUCTURE : balanced. Brackets, quotes and here-strings all close.")
        print()

    if colon_hits:
        print(f"INVALID VARIABLE REFERENCES ({len(colon_hits)}) - these stop the file loading:")
        for line_no, var, src in colon_hits:
            print(f"  line {line_no:>5}: \"${var}:\" must be written \"${{{var}}}:\"")
            print(f"              | {src[:100]}")
        print()
    else:
        print("VARIABLES : no invalid \"$name:\" drive-qualified references.")
        print()

    if missing:
        print("CALLED BUT NOT DEFINED (check these are real cmdlets):")
        for name, count in sorted(missing.items(), key=lambda kv: -kv[1]):
            print(f"  {name:<34} x{count}")
        print()
    else:
        print("CALLS     : every Verb-Noun call resolves to a definition or a known cmdlet.")
        print()

    return 1 if (errors or colon_hits) else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'ARGUS.ps1'))
