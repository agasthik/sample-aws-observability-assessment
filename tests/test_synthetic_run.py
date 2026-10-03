# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Exercise the complete assessment without contacting AWS."""

import contextlib
import csv
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from observability_assessment_comprehensive import ComprehensiveObservabilityAssessment


class SyntheticAssessmentTests(unittest.TestCase):
    def test_entrypoint_imports_package_from_sibling_checkout(self):
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "assessment-src"
            checkout.mkdir()
            entrypoint = checkout / "observability_assessment_comprehensive.py"
            shutil.copy2(
                repository / "observability_assessment_comprehensive.py", entrypoint
            )
            shutil.copytree(
                repository / "observability_assessment",
                checkout / "observability_assessment",
                ignore=shutil.ignore_patterns("__pycache__"),
            )

            result = subprocess.run(
                [sys.executable, str(entrypoint), "--help"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--single-question", result.stdout)

    def test_full_run_writes_reports(self):
        assessment = ComprehensiveObservabilityAssessment(region="us-west-2")
        assessment.timestamp = "20261002_000000"

        def aws_result(command, *_args, **_kwargs):
            if "sts get-caller-identity" in command:
                return {
                    "Account": "111111111111",
                    "Arn": "arn:aws:iam::111111111111:role/Synthetic",
                }
            if "logs describe-log-groups" in command:
                return {"logGroups": []}
            return {}

        assessment.run_aws_command = aws_result

        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            try:
                os.chdir(directory)
                with contextlib.redirect_stdout(io.StringIO()):
                    assessment.run_full_assessment()

                self.assertEqual(len(assessment.results.discovery_checks), 52)
                self.assertEqual(len(assessment.results.assessment_checks), 17)
                self.assertEqual(
                    Counter(c.status for c in assessment.results.discovery_checks),
                    {"success": 52},
                )
                self.assertEqual(assessment.results.overall_score, 1.0)
                self.assertEqual(assessment.results.maturity_level, "Reactive")

                csv_path = Path(assessment.csv_file)
                html_path = Path(assessment.html_file)
                self.assertTrue(csv_path.is_file())
                self.assertTrue(html_path.is_file())
                self.assertIn("111111111111", csv_path.name)
                self.assertIn("111111111111", html_path.name)
                with csv_path.open(newline="") as stream:
                    self.assertEqual(len(list(csv.reader(stream))), 53)
                self.assertIn(
                    "AWS Observability Assessment Report",
                    html_path.read_text(encoding="utf-8"),
                )
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
