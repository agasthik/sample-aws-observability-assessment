# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Boundaries of the Reactive / Proactive / Autonomous maturity bands."""

import unittest

from observability_assessment.models import maturity_label


class MaturityLabelTests(unittest.TestCase):
    def test_band_boundaries(self):
        cases = {
            1.0: "Reactive",
            1.99: "Reactive",
            2.0: "Proactive",
            3.0: "Proactive",
            3.49: "Proactive",
            3.5: "Autonomous",
            4.0: "Autonomous",
        }
        for score, label in cases.items():
            with self.subTest(score=score):
                self.assertEqual(maturity_label(score), label)


if __name__ == "__main__":
    unittest.main()
