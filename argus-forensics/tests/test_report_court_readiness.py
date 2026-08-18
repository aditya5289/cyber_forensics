"""What the report must say to survive cross-examination.

A forensic report is not a data dump. It is a document someone will be
questioned on, and the questions are predictable: what tool produced this, what
version, how do you know it was not altered, how do you know the evidence was
not altered, what did you actually do, and what did you not do.

The report answered none of the first four until this suite was written. It
described 617 artifacts in detail and never named the software that decoded
them.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"))

from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan
from argus.analyze.session import AnalysisSession
from argus.core.case import Case, Exhibit
from argus.report.builder import ReportBuilder, ReportOptions

import make_device


def _plain(html_text: str) -> str:
    text = re.sub(r"<script.*?</script>", " ", html_text, flags=re.S)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text))


class ReportIdentifiesItself(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="argus-report-"))
        evidence = cls.tmp / "evidence"
        make_device.build_android(evidence)

        case = Case.create(cls.tmp / "cases", case_id="RPT",
                           investigator="A. Sharma")
        case.add_exhibit(Exhibit("EXH-1", make="Samsung",
                                 model="Galaxy S21 5G"))
        report = AcquisitionEngine(case).run(AcquisitionPlan(
            method="import", source_path=evidence, operator="A. Sharma",
            exhibit_id="EXH-1", device_name="Samsung Galaxy S21 5G"))

        cls.session = AnalysisSession([Path(report.container)])
        builder = ReportBuilder(cls.session, ReportOptions(formats=["html"]))
        written = builder.write(cls.tmp / "out")
        cls.html = Path(written[0]).read_text(encoding="utf-8")
        cls.text = _plain(cls.html)
        cls.builder = builder

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.session.close()
        except Exception:
            pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------- tool identity
    def test_names_the_product_and_version(self) -> None:
        self.assertIn("ARGUS Forensics", self.text)
        self.assertRegex(self.text, r"\b\d+\.\d+\.\d+\b")

    def test_states_the_build_identifier(self) -> None:
        """A validation certificate is issued against a build, not a product."""
        build = self.builder._tool["build"]
        self.assertTrue(build, "no build identifier was computed")
        self.assertIn(build[:16], self.text)

    def test_states_whether_the_installation_was_verified(self) -> None:
        self.assertRegex(
            self.text,
            r"(?i)(files match the release manifest"
            r"|DOES NOT MATCH THE RELEASE MANIFEST"
            r"|could not be checked against a release manifest)")

    def test_an_unverified_build_says_so_rather_than_staying_silent(self) -> None:
        """Silence would read as verified. It must not."""
        tool = self.builder._tool
        if not tool["build"] or tool["verification"] == "not verified":
            self.assertIn("could not be checked", tool["note"])

    def test_records_the_runtime(self) -> None:
        self.assertIn("Python", self.text)

    # -------------------------------------------------------- evidence seal
    def test_publishes_the_container_seal(self) -> None:
        """Claiming "sealed" without the digest asks the reader to take it on
        trust. Publishing it lets anyone recompute and check."""
        seal = self.builder._seal["container_seal"]
        self.assertNotEqual(seal, "—")
        self.assertEqual(len(seal), 64, "expected a SHA-256 digest")
        self.assertIn(seal[:16], self.text)

    def test_publishes_the_blob_merkle_root(self) -> None:
        root = self.builder._seal["blob_merkle_root"]
        self.assertNotEqual(root, "—")
        self.assertIn(root[:16], self.text)

    def test_states_the_audit_chain_status(self) -> None:
        self.assertRegex(self.text, r"(?i)audit chain")
        self.assertIn(self.builder._seal["audit"], self.text)

    def test_tells_the_reader_how_to_verify_independently(self) -> None:
        self.assertIn("argus verify", self.text)

    # ------------------------------------------------------------ method
    def test_describes_what_was_actually_done(self) -> None:
        for phrase in ("capability matrix", "magic bytes", "unallocated",
                       "normalised", "sealed"):
            self.assertIn(phrase, self.text, phrase)

    def test_states_that_the_evidence_was_not_modified(self) -> None:
        self.assertRegex(self.text, r"(?i)without modification|immutable")

    def test_report_is_generated_from_the_sealed_container(self) -> None:
        """Not from the live filesystem — which would be unreproducible."""
        self.assertIn("sealed container", self.text)

    # ------------------------------------------------- examiner attribution
    def test_examiner_falls_back_to_the_recorded_operator(self) -> None:
        """The operator is captured at acquisition.

        Leaving Examiner blank when the container already knows who ran the
        extraction produces a report with no named author, which is worse than
        useless in a bundle.
        """
        section = re.search(
            r"1\. Case and exhibit(.*?)2\. Tool", self.text, re.S)
        self.assertIsNotNone(section)
        self.assertIn("A. Sharma", section.group(1))

    # ------------------------------------------------------------ structure
    def test_sections_are_numbered_consecutively(self) -> None:
        numbers = [int(m) for m in
                   re.findall(r"<h2[^>]*>(\d+)\.", self.html)]
        self.assertEqual(numbers, list(range(1, len(numbers) + 1)),
                         f"section numbering is not consecutive: {numbers}")

    def test_integrity_precedes_the_findings(self) -> None:
        """A reader who reaches the findings first has already been misled if
        verification failed."""
        self.assertLess(self.html.index("Tool, method and integrity"),
                        self.html.index("Investigative findings"))


if __name__ == "__main__":
    unittest.main()
