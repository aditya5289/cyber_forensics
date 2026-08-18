#!/bin/bash
# ===================================================================
#  ARGUS Forensics - Linux launcher
#  Double-click this file (or run ./ARGUS.sh) to start the application.
#  (If macOS refuses: right-click -> Open, or run
#   chmod +x ARGUS.command once from Terminal.)
# ===================================================================
cd "$(dirname "$0")" || exit 1

find_python() {
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)' 2>/dev/null; then
                echo "$candidate"; return 0
            fi
        fi
    done
    return 1
}

PY=$(find_python)
if [ -z "$PY" ]; then
    cat <<'MSG'

  ----------------------------------------------------------------
   ARGUS cannot start: Python 3.10 or newer was not found.
  ----------------------------------------------------------------

   Install it with either:
       sudo apt install python3
   or download from:
       https://www.python.org/downloads/

   Then run this launcher again.

MSG
    read -r -p "  Press Enter to close… "
    exit 1
fi

echo
echo "  Starting ARGUS Forensics…"
echo "  A browser window will open shortly."
echo "  Keep this window open while you work — closing it stops ARGUS."
echo

"$PY" "$(pwd)/argus_app.py" "$@"
RC=$?
if [ "$RC" -ne 0 ]; then
    echo
    echo "  ARGUS exited with code $RC."
    read -r -p "  Press Enter to close… "
fi
