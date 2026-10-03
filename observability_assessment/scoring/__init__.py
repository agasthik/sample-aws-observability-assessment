# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Maturity scoring methods for the observability assessment."""

from .dashboards import DashboardsScoringMixin as _DashboardsScoringMixin
from .logs import LogsScoringMixin as _LogsScoringMixin
from .metrics import MetricsScoringMixin as _MetricsScoringMixin
from .orchestration import CategoryAssessmentMixin as _CategoryAssessmentMixin
from .organization import OrganizationScoringMixin as _OrganizationScoringMixin
from .questions import QuestionScoringMixin as _QuestionScoringMixin
from .traces import TracesScoringMixin as _TracesScoringMixin


class ScoringMixin(
    _CategoryAssessmentMixin,
    _QuestionScoringMixin,
    _LogsScoringMixin,
    _MetricsScoringMixin,
    _TracesScoringMixin,
    _DashboardsScoringMixin,
    _OrganizationScoringMixin,
):
    """Question setup, category scoring, and discovery mapping for an assessment.

    The host supplies ``results`` and ``largest_log_groups``.
    """


__all__ = ["ScoringMixin"]
