# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Contracts for the sample-report scrubbing script."""

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "scrub-sample-report.py"
spec = importlib.util.spec_from_file_location("scrub_sample_report", SCRIPT)
scrub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scrub)


class StripReportTimestampsTests(unittest.TestCase):
    def test_strips_account_report_links(self):
        content = (
            '<a href="observability_assessment_20261003_050805_111122223333.html">'
            '"link":"observability_assessment_20261003_051143_222233334444.html"'
        )
        self.assertEqual(
            scrub.strip_report_timestamps(content),
            '<a href="observability_assessment_111122223333.html">'
            '"link":"observability_assessment_222233334444.html"',
        )

    def test_strips_summary_back_link(self):
        self.assertEqual(
            scrub.strip_report_timestamps(
                '"backLink":"organization_summary_20261003_050758.html"'
            ),
            '"backLink":"organization_summary.html"',
        )

    def test_leaves_other_text_untouched(self):
        content = (
            '"generatedAt":"2026-10-03T05:15:25+00:00" '
            "observability_assessment_single_account_sample.html 20261003_050805"
        )
        self.assertEqual(scrub.strip_report_timestamps(content), content)


if __name__ == "__main__":
    unittest.main()
