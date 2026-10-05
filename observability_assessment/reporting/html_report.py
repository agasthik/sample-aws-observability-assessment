# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Self-contained Cloudscape HTML assessment report."""

from pathlib import Path

from observability_assessment.models import maturity_label

from .cloudscape_bridge import assessment_payload, inline_report


class HtmlReportingMixin:
    def generate_html_report(self):
        """Write the current assessment as a standalone Cloudscape report."""
        self.results.overall_score = self.compute_overall_score()
        self.results.timestamp = self.timestamp
        self.results.maturity_level = (
            maturity_label(self.results.overall_score)
            if self.results.overall_score is not None
            else "Not assessed"
        )
        html_content = inline_report(assessment_payload(self))
        report_path = Path(self.html_file)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(html_content, encoding="utf-8")
