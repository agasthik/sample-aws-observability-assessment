# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Report wording and the evidence fields it reads from discovery results."""

import ast
import unittest
from pathlib import Path

from observability_assessment.discovery.check_specs import CHECK_SPECS
from observability_assessment.text import plural
from test_characterization import configured_assessment, discovery, question


class PluralTests(unittest.TestCase):
    def test_singular_plural_and_irregular_forms(self):
        self.assertEqual(plural(1, "alarm"), "1 alarm")
        self.assertEqual(plural(0, "alarm"), "0 alarms")
        self.assertEqual(plural(2, "alarm"), "2 alarms")
        self.assertEqual(plural(1, "query", "queries"), "1 query")
        self.assertEqual(plural(3, "query", "queries"), "3 queries")


class EvidenceFieldTests(unittest.TestCase):
    def test_metrics_maturity_credits_eks_observability_addon(self):
        assessment = configured_assessment()
        target = question(assessment, 5)
        assessment.results.assessment_checks = [target]
        assessment.largest_log_groups = {"EKS": ["/aws/containerinsights/orders"]}
        eks_addon = discovery(assessment, 21)
        eks_addon.status = "success"
        eks_addon.result = {"total_clusters": 1, "observability_clusters": 1}

        assessment.assess_metrics_maturity()

        self.assertEqual(target.current_level, 2)
        self.assertIn("EKS CloudWatch Observability add-on", target.explanation)

    def test_ecs_container_evidence_reads_discovery_keys(self):
        assessment = configured_assessment()
        check = discovery(assessment, 9)
        check.result = {
            "clusters": ["orders"],
            "running_tasks": ["task-1"],
            "tasks_with_logging": ["task-1"],
            "logging_configs": [
                {
                    "taskDefinition": "orders",
                    "containers": [
                        {
                            "container": "app",
                            "logDriver": "awslogs",
                            "options": {"awslogs-group": "/ecs/orders"},
                        }
                    ],
                }
            ],
        }

        evidence = assessment.generate_detailed_evidence(check)

        self.assertIn(
            "Container 1: app | Driver: awslogs | Group: /ecs/orders", evidence
        )

    def test_retention_evidence_handles_missing_policy_and_group_count(self):
        assessment = configured_assessment()
        check = discovery(assessment, 2)
        check.result = {
            "top_log_groups": [
                {"name": "/app/never", "size_mb": 10.0, "retention_days": None},
                {"name": "/app/week", "size_mb": 5.0, "retention_days": 7},
            ],
            "groups_with_retention": 1,
            "total_size_gb": 0.0,
        }

        evidence = assessment.generate_detailed_evidence(check)

        self.assertIn("Analyzed the 2 largest log groups", evidence)
        self.assertIn("1/2 have retention policies", evidence)
        self.assertIn("Retention: Never expire", evidence)
        self.assertIn("Retention: 7 days", evidence)
        self.assertNotIn("None days", evidence)

    def test_eks_control_plane_evidence_does_not_claim_all_clusters(self):
        assessment = configured_assessment()
        check = discovery(assessment, 10)
        check.result = {
            "clusters": [
                {"cluster": "a", "enabled_types": ["api", "audit"]},
                {"cluster": "b", "enabled_types": []},
            ],
            "enabled_types": 2,
        }

        evidence = assessment.generate_detailed_evidence(check)

        self.assertIn("Found 2 EKS clusters", evidence)
        self.assertIn("enabled on at least one cluster", evidence)
        self.assertNotIn("across all clusters", evidence)

    def test_query_history_evidence_counts_custom_queries(self):
        assessment = configured_assessment()
        check = discovery(assessment, 4)
        check.result = {
            "queries": [
                {
                    "queryId": "abcdef123456",
                    "queryString": "fields @message | filter level = 'ERROR'",
                    "status": "Complete",
                },
                {
                    "queryId": "zzz",
                    "queryString": 'SOURCE "/aws/application-signals/data"',
                    "status": "Complete",
                },
            ]
        }

        evidence = assessment.generate_detailed_evidence(check)

        self.assertIn("Found 1 custom query (filtered from 2 total)", evidence)
        self.assertIn("ID:abcdef12 Status:Complete", evidence)
        self.assertIn("filter level = &#x27;ERROR&#x27;", evidence)

    def test_json_structured_logs_evidence_reports_ratio_and_examples(self):
        assessment = configured_assessment()
        check = discovery(assessment, 16)
        check.result = {
            "total_groups_checked": 5,
            "json_groups": 2,
            "sample_groups": ["/app/orders", "/app/payments"],
        }

        evidence = assessment.generate_detailed_evidence(check)

        self.assertIn("Analyzed the 5 largest log groups", evidence)
        self.assertIn("2/5 have JSON structured logs", evidence)
        self.assertIn("Examples: /app/orders, /app/payments", evidence)

    def test_xray_service_map_evidence_names_services(self):
        assessment = configured_assessment()
        check = discovery(assessment, 26)
        check.result = {"Services": [{"Name": "orders"}, {"Name": "payments"}]}

        evidence = assessment.generate_detailed_evidence(check)

        self.assertIn("Found 2 X-Ray services (e.g., orders, payments)", evidence)

    def test_evidence_has_no_unreachable_top_level_statements(self):
        """A top-level branch that always returns makes anything after it dead."""
        source = (
            Path(__file__).resolve().parents[1]
            / "observability_assessment/reporting/evidence.py"
        ).read_text()
        function = next(
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.FunctionDef)
            and node.name == "generate_detailed_evidence"
        )

        def always_returns(statement):
            if isinstance(statement, ast.Return):
                return True
            return (
                isinstance(statement, ast.If)
                and bool(statement.orelse)
                and any(always_returns(s) for s in statement.body)
                and any(always_returns(s) for s in statement.orelse)
            )

        terminal = [i for i, s in enumerate(function.body) if always_returns(s)]
        self.assertEqual(terminal, [len(function.body) - 1])


class CheckNameLookupTests(unittest.TestCase):
    """Check names are matched by exact string, so a rename must reach every use."""

    names = {spec.name for spec in CHECK_SPECS}

    def test_question_mappings_reference_existing_checks(self):
        assessment = configured_assessment()
        for question_id in range(1, 18):
            for name in assessment.get_discovery_checks_for_question(question_id):
                self.assertIn(name, self.names, f"question {question_id}")

    def test_scoring_and_reporting_lookups_reference_existing_checks(self):
        package = Path(__file__).resolve().parents[1] / "observability_assessment"
        paths = (
            path
            for section in ("scoring", "reporting")
            for path in (package / section).glob("*.py")
        )
        for path in paths:
            for node in ast.walk(ast.parse(path.read_text())):
                if not (
                    isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.Eq)
                ):
                    continue
                left, right = node.left, node.comparators[0]
                if isinstance(left, ast.Attribute) and left.attr == "name":
                    if isinstance(right, ast.Constant) and isinstance(right.value, str):
                        self.assertIn(
                            right.value, self.names, f"{path.name}:{right.lineno}"
                        )


if __name__ == "__main__":
    unittest.main()
