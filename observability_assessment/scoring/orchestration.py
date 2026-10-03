# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Assessment scoring for orchestration."""

CATEGORIES = (
    "Logs",
    "Metrics",
    "Traces",
    "Dashboards & Alerting",
    "Organization",
)


def assessed_questions(questions):
    """Questions that count toward scores (excludes "Not assessed")."""
    return [q for q in questions if q.assessed]


def average_level(questions):
    """Mean maturity level of assessed questions, or None if none were assessed."""
    scored = assessed_questions(questions)
    if not scored:
        return None
    return sum(q.current_level for q in scored) / len(scored)


class CategoryAssessmentMixin:
    """Scoring methods that operate on ``self.results``."""

    def assess_all_categories(self):
        """Assess maturity for all categories based on discovery checks"""
        self.assess_logs_maturity()
        self.assess_metrics_maturity()
        self.assess_traces_maturity()
        self.assess_dashboards_alarms_maturity()
        self.assess_organization_maturity()
        self.apply_evidence_availability()

        # Store per-category average maturity so multi-account aggregation and
        # the org summary have data to roll up (mirrors the radar-chart formula).
        # Categories with no assessed questions are omitted rather than scored 0.
        self.results.category_scores = {}
        for cat in CATEGORIES:
            checks = [c for c in self.results.assessment_checks if c.category == cat]
            score = average_level(checks)
            if score is not None:
                self.results.category_scores[cat] = score

    def apply_evidence_availability(self):
        """Mark questions whose evidence checks errored or were incomplete.

        A question with no evaluable evidence is "Not assessed": its level
        would only reflect missing data, so it is excluded from averages. A
        question with some unavailable or incomplete evidence keeps its level,
        which is then a lower bound, and the report flags it.
        """
        checks_by_id = {c.id: c for c in self.results.discovery_checks}
        for question in self.results.assessment_checks:
            evidence = [
                checks_by_id[i]
                for i in question.evidence_check_ids
                if i in checks_by_id
            ]
            question.unavailable_check_ids = [
                c.id for c in evidence if c.status == "error"
            ]
            question.incomplete_check_ids = [
                c.id
                for c in evidence
                if c.status == "success"
                and isinstance(c.result, dict)
                and c.result.get("failed_lookups", 0) > 0
            ]
            if question.current_level is None:
                question.assessed = False
                question.explanation = (
                    "Not assessed: no scoring rule assigned a maturity level."
                )
                continue
            question.assessed = not evidence or any(
                c.status == "success" for c in evidence
            )
            if not question.assessed:
                question.explanation = (
                    "Not assessed: none of the evidence checks could be "
                    "evaluated (likely missing permissions, throttling, or CLI "
                    "errors). Re-run with --debug for details."
                )

    def compute_overall_score(self):
        """Mean level of assessed questions, or None when none were assessed."""
        return average_level(self.results.assessment_checks)
