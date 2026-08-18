"""Desktop sidecar contract tests (Tauri integration)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "argus_app.py"


class TestDesktopSidecar(unittest.TestCase):
    def test_ready_json_emits_valid_event(self):
        proc = subprocess.Popen(
            [sys.executable, str(APP), "--no-browser", "--quiet",
             "--ready-json", "--port", "0", "--token", "desktop-test-token"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(ROOT),
        )
        try:
            line = proc.stdout.readline()
            evt = json.loads(line)
            self.assertEqual(evt["event"], "ready")
            self.assertEqual(evt["token"], "desktop-test-token")
            self.assertGreater(evt["port"], 0)
            self.assertIn("url", evt)
            self.assertIn("version", evt)
            self.assertIn("build", evt)

            ping = urllib.request.urlopen(
                f"http://127.0.0.1:{evt['port']}/api/ping?token={evt['token']}",
                timeout=5,
            )
            self.assertEqual(ping.status, 200)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    unittest.main()
