"""dumpsys communication parser tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argus.parsers.android.dumpsys_comms import parse_dumpsys
from argus.parsers.registry import ParseContext


class TestDumpsysComms(unittest.TestCase):
    def test_call_log_lines(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "call_log.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "CallLog calls:\n"
                "number=+919876543210, date=1700000000000, duration=42\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertEqual(res.artifacts[0].category.value, "Calls")

    def test_location_line(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "location.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Last known location: latitude=12.971600 longitude=77.594600\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertIsNotNone(res.artifacts[0].latitude)

    def test_telecom_call_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "telecom.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Call 0: TC@5\n"
                "\thandle: tel:+15551212999\n"
                "\tstate: DISCONNECTED\n"
                "\tisIncoming: true\n"
                "\tconnectTimeMillis: 1700000000000\n"
                "\tdisconnectTimeMillis: 1700000012000\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertEqual(res.artifacts[0].category.value, "Calls")
            self.assertIn("5551212999", res.artifacts[0].body.replace(" ", ""))

    def test_messaging_notification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "notification.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "NotificationRecord(0x1)\n"
                "  opPkg=com.samsung.android.messaging uid=10123\n"
                "  when=1700000000000\n"
                "  extras={\n"
                "    android.title=Mom\n"
                "    android.text=Call me when you land\n"
                "  }\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertEqual(res.artifacts[0].category.value, "Messages")
            self.assertIn("Call me when you land", res.artifacts[0].body)

    def test_subscription_msisdn(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "isub.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "SubscriptionInfo: id=1 iccId=89014103211118510720 "
                "number=+15550001999 displayName=Jio\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            kinds = {a.subtype for a in res.artifacts}
            self.assertTrue("Subscriber number" in kinds or "SIM ICCID" in kinds)

    def test_multiline_call_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "call_log.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Call record:\n"
                "  number: +919876543210\n"
                "  date: 1700000000000\n"
                "  duration: 42\n"
                "  type: 2\n"
                "  name: Mom\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertEqual(res.artifacts[0].category.value, "Calls")
            self.assertIn("9876543210", res.artifacts[0].body.replace(" ", ""))

    def test_multiline_sms_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "sms.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "SmsMessage {\n"
                "  originatingAddress=+15551212000\n"
                "  messageBody=Where are you\n"
                "  date=1700000000000\n"
                "}\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertEqual(res.artifacts[0].category.value, "Messages")
            self.assertIn("Where are you", res.artifacts[0].body)


if __name__ == "__main__":
    unittest.main()
