# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Command-line entry point and public API for the AWS Observability Assessment."""

from observability_assessment.assessment import ComprehensiveObservabilityAssessment
from observability_assessment.cli import main
from observability_assessment.models import (
    AssessmentResults,
    DiscoveryCheck,
    ObservabilityCheck,
    OrganizationAssessmentResults,
)
from observability_assessment.orchestration import MultiAccountAssessment

__all__ = [
    "AssessmentResults",
    "ComprehensiveObservabilityAssessment",
    "DiscoveryCheck",
    "MultiAccountAssessment",
    "ObservabilityCheck",
    "OrganizationAssessmentResults",
    "main",
]

if __name__ == "__main__":
    main()
