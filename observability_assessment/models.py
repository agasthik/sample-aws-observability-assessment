# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Result models shared by assessment, scoring, and reporting."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def maturity_label(score: float) -> str:
    """Name the maturity band for an overall, category, or question score (1-4)."""
    if score >= 3.5:
        return "Autonomous"
    if score >= 2:
        return "Proactive"
    return "Reactive"


@dataclass
class DiscoveryCheck:
    """Individual discovery check with unique ID"""

    id: int
    name: str
    category: str
    command: str
    result: Optional[Any] = None
    status: str = "pending"  # pending, success, error
    evidence: str = ""


@dataclass
class ObservabilityCheck:
    """Assessment question with maturity levels"""

    question_id: int
    category: str
    question: str
    # None until a scoring rule assigns a level.
    current_level: Optional[int] = None
    target_level: int = 4
    evidence_check_ids: List[int] = field(default_factory=list)
    explanation: str = ""
    remediation: str = ""
    maturity_descriptions: Dict[int, str] = field(default_factory=dict)
    # True only once a level was scored from at least one evaluable evidence
    # check; otherwise the question is reported as "Not assessed" and left out
    # of all averages.
    assessed: bool = False
    # Evidence checks that errored (permissions, throttling, CLI failure).
    unavailable_check_ids: List[int] = field(default_factory=list)
    # Evidence checks that succeeded but could not read some resources.
    incomplete_check_ids: List[int] = field(default_factory=list)


@dataclass
class AssessmentResults:
    """Complete assessment results"""

    account_id: str = ""
    user_arn: str = ""
    discovery_checks: List[DiscoveryCheck] = field(default_factory=list)
    assessment_checks: List[ObservabilityCheck] = field(default_factory=list)
    category_scores: Dict[str, float] = field(default_factory=dict)
    overall_score: Optional[float] = None
    maturity_level: str = ""
    timestamp: str = ""


@dataclass
class OrganizationAssessmentResults:
    """Aggregated results across all assessed accounts"""

    organization_id: str = ""
    management_account_id: str = ""
    account_results: Dict[str, AssessmentResults] = field(default_factory=dict)
    account_names: Dict[str, Optional[str]] = field(default_factory=dict)
    failed_accounts: Dict[str, str] = field(default_factory=dict)
    category_scores_avg: Dict[str, float] = field(default_factory=dict)
    category_scores_min: Dict[str, float] = field(default_factory=dict)
    category_scores_max: Dict[str, float] = field(default_factory=dict)
    # None when no account had an assessed question.
    overall_score_avg: Optional[float] = None
    overall_score_min: Optional[float] = None
    overall_score_max: Optional[float] = None
    maturity_level: str = ""
    best_maturity_level: str = ""
    summary_report_filename: str = ""
    timestamp: str = ""
