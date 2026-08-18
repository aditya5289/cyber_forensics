"""Parser registry path matching."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argus.parsers.registry import ParseContext, parsers_for


class TestParserPathMatching(unittest.TestCase):
    def test_adb_content_matches_windows_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "content" / "sms_sent.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "Row: 0 _id=1, address=+15551212, body=hello, type=2\n",
                encoding="utf-8",
            )
            specs = parsers_for(path, "android")
            names = [s.name for s in specs]
            self.assertIn("android.adb_content", names)


if __name__ == "__main__":
    unittest.main()
