# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Reporting methods for comprehensive observability assessments."""

from .csv_export import CsvReportingMixin
from .evidence import EvidenceReportingMixin
from .html_report import HtmlReportingMixin
from .recommendations import RecommendationReportingMixin


class ReportingMixin(
    CsvReportingMixin,
    EvidenceReportingMixin,
    RecommendationReportingMixin,
    HtmlReportingMixin,
):
    """CSV, evidence, recommendation, and self-contained HTML reporting."""


__all__ = ["ReportingMixin"]
