# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import time
from datetime import datetime

from .aws import AwsMixin
from .discovery import DiscoveryMixin
from .models import AssessmentResults
from .text import plural
from .reporting import ReportingMixin
from .scoring import ScoringMixin


class ComprehensiveObservabilityAssessment(
    AwsMixin, DiscoveryMixin, ScoringMixin, ReportingMixin
):
    """Coordinate one account's assessment."""

    def __init__(
        self,
        profile=None,
        region="us-west-2",
        role_arn=None,
        summary_report_filename=None,
    ):
        self.profile = profile
        self.region = region
        self.results = AssessmentResults()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.html_file = None  # Set after getting account_id
        self.discovery_check_counter = 0
        self.largest_log_groups = None  # Populated during setup
        self.csv_file = None  # Set after getting account_id
        self.env_override = None  # For assumed role credentials
        self.summary_report_filename = (
            summary_report_filename  # For multi-account back-link
        )

        if role_arn:
            self._assume_role(role_arn)

    def run_single_question(self, question_id: int):
        """Run only the discovery checks relevant to a specific assessment question and score it."""
        print(f"Running Assessment Question #{question_id}")
        print("=" * 60)

        self.setup_discovery_checks()

        identity = self.run_aws_command("aws sts get-caller-identity --output json")
        if not identity:
            print("[ERROR] Could not get AWS identity")
            return False
        self.results.account_id = identity.get("Account", "Unknown")
        self.results.user_arn = identity.get("Arn", "Unknown")

        # Run only relevant discovery checks
        needed_names = self.get_discovery_checks_for_question(question_id)
        if not needed_names:
            print(
                f"[ERROR] No discovery check mapping defined for question {question_id}"
            )
            return False

        relevant_checks = [
            c for c in self.results.discovery_checks if c.name in needed_names
        ]
        print(
            f"Running {plural(len(relevant_checks), 'discovery check')} for question {question_id}:\n"
        )
        for c in relevant_checks:
            print(f"  - #{c.id}: {c.name[:80]}...")
            self.execute_discovery_check(c.id)
            _icon = {"success": "[OK]", "error": "[WARN]"}.get(c.status, "[ERROR]")
            print(f"     Status: {_icon} ({c.status})")

        # Setup and run maturity assessment
        self.setup_assessment_questions()
        category_map = {
            1: "Logs",
            2: "Logs",
            3: "Logs",
            4: "Logs",
            5: "Metrics",
            6: "Metrics",
            7: "Metrics",
            8: "Traces",
            9: "Traces",
            10: "Dashboards & Alerting",
            11: "Dashboards & Alerting",
            12: "Dashboards & Alerting",
            13: "Organization",
            14: "Organization",
            15: "Organization",
            16: "Organization",
            17: "Organization",
        }
        cat = category_map.get(question_id)
        if cat == "Logs":
            self.assess_logs_maturity()
        elif cat == "Metrics":
            self.assess_metrics_maturity()
        elif cat == "Traces":
            self.assess_traces_maturity()
        elif cat == "Dashboards & Alerting":
            self.assess_dashboards_alarms_maturity()
        elif cat == "Organization":
            self.assess_organization_maturity()
        self.apply_evidence_availability()

        q = next(
            (c for c in self.results.assessment_checks if c.question_id == question_id),
            None,
        )
        if q:
            print(f"\n{'=' * 60}")
            print(f"Question {question_id}: {q.question}")
            if q.assessed:
                print(
                    f"   Level: {q.current_level}/4 — {q.maturity_descriptions.get(q.current_level, '')}"
                )
            else:
                print(
                    "   Level: [WARN] Not assessed (no evidence check could be evaluated)"
                )
            if q.assessed and q.unavailable_check_ids:
                print(
                    f"   [WARN] Unavailable checks: {q.unavailable_check_ids} -- level may understate maturity"
                )
            if q.incomplete_check_ids:
                print(f"   [WARN] Partial data in checks: {q.incomplete_check_ids}")
            print(f"   Explanation: {q.explanation}")
        print("\n[OK] Single question assessment complete!")
        return True

    def run_single_check(self, check_id: int):
        """Run a single discovery check and output to console"""
        print(f"Running Single Discovery Check #{check_id}")
        print("=" * 60)

        # Setup discovery checks to get the check definition
        self.setup_discovery_checks()

        # Find the requested check
        target_check = next(
            (c for c in self.results.discovery_checks if c.id == check_id), None
        )
        if not target_check:
            print(f"[ERROR] Check #{check_id} not found")
            print(f"Available checks: 1-{len(self.results.discovery_checks)}")
            return False

        # Get AWS identity
        identity = self.run_aws_command("aws sts get-caller-identity --output json")
        if not identity:
            print("[ERROR] Could not get AWS identity")
            return False

        self.results.account_id = identity.get("Account", "Unknown")
        self.results.user_arn = identity.get("Arn", "Unknown")

        print("Check Details:")
        print(f"   ID: {target_check.id}")
        print(f"   Name: {target_check.name}")
        print(f"   Category: {target_check.category}")
        print(f"   Command: {target_check.command}")
        print()

        # Execute the specific check
        print("Executing check...")
        self.execute_discovery_check(check_id)

        # Display results
        print("Results:")
        print(
            f"   Status: {'SUCCESS' if target_check.status == 'success' else ('UNAVAILABLE' if target_check.status == 'error' else 'NOT RUN')}"
        )
        print(f"   Evidence: {target_check.evidence}")
        print()

        if target_check.status != "success":
            print("[ERROR] Single check could not be evaluated")
            return False
        print("[OK] Single check complete!")
        return True

    def run_assessment(self):
        """Run the full comprehensive assessment"""
        return self.run_full_assessment()

    def run_full_assessment(self):
        """Run the complete assessment. Returns False if the AWS identity cannot be resolved."""
        started = time.monotonic()
        print("Starting Comprehensive Observability Assessment")
        print("=" * 80)

        # Get AWS identity
        identity = self.run_aws_command("aws sts get-caller-identity --output json")
        if not identity:
            # Without a resolvable identity every check would fail and the report
            # would read as missing observability, so stop instead of scoring.
            print("[ERROR] Could not get AWS identity -- aborting assessment")
            return False
        self.results.account_id = identity.get("Account", "Unknown")
        self.results.user_arn = identity.get("Arn", "Unknown")
        self.html_file = f"assessment-result/observability_assessment_{self.timestamp}_{self.results.account_id}.html"

        # Setup and execute discovery
        self.setup_discovery_checks()
        self.execute_all_discovery_checks()

        # Setup assessment questions
        self.setup_assessment_questions()

        # Perform assessments
        self.assess_all_categories()

        # Generate report
        self.generate_html_report()

        self.print_assessment_summary(time.monotonic() - started)
        return True

    def print_assessment_summary(self, elapsed_seconds=None):
        """Print the end-of-run highlights as a separate block."""
        checks = self.results.discovery_checks
        successful = sum(1 for c in checks if c.status == "success")
        rows = [
            ("Account", self.results.account_id),
            ("Region", self.region),
            ("Discovery", f"{successful}/{len(checks)} checks successful"),
            (
                "Overall Score",
                f"{self.results.overall_score:.1f}/4.0"
                if self.results.overall_score is not None
                else "N/A",
            ),
            ("Maturity Level", self.results.maturity_level),
            ("HTML report", self.html_file),
        ]
        if elapsed_seconds is not None:
            minutes, seconds = divmod(round(elapsed_seconds), 60)
            rows.append(("Total Time", f"{minutes}m {seconds:02d}s"))
        print()
        print("=" * 80)
        if any(q.assessed for q in self.results.assessment_checks):
            print("[OK] Assessment complete!")
        else:
            print(
                "[WARN] Assessment finished, but no questions could be scored "
                "(no evidence check could be evaluated)"
            )
        print("-" * 80)
        for label, value in rows:
            print(f"  {label + ':':<16} {value}")
        print("=" * 80)
