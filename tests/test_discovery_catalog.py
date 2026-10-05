# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Contracts for built-in discovery identities and command dispatch."""

import contextlib
import io
import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from observability_assessment.assessment import ComprehensiveObservabilityAssessment
from observability_assessment.discovery import executor
from observability_assessment.discovery.check_specs import (
    CHECK_SPECS,
    CHECK_SPECS_BY_ID,
    CHECK_SPECS_BY_KEY,
)


FIXTURE = Path(__file__).with_name("discovery_catalog.json")
EXPECTED_KEYS = """\
log_group_source_classification
log_group_retention
logs_insights_queries
logs_insights_query_history
log_metric_filters
log_subscription_coverage
ec2_agent_logs
lambda_json_logging
ecs_structured_logging
eks_control_plane_logs
eks_observability_addon_logs
log_anomaly_detectors
log_export_tasks
log_centralization
cross_account_observability
application_json_logging
log_field_indexes
ec2_detailed_monitoring
ecs_clusters
ecs_container_insights
eks_observability_addon_metrics
lambda_insights
custom_metric_namespaces
cloudwatch_agent_metrics
metric_streams
xray_service_map
xray_sampling_rules
xray_groups
transaction_search
lambda_xray_tracing
xray_insights
xray_annotations
cloudwatch_dashboards
cloudwatch_alarms
composite_alarms
alarm_sns_actions
alarm_anomaly_detection
resource_tags
synthetics_canaries
rum_app_monitors
alarm_opsitem_actions
devops_agent_spaces
alarm_lambda_actions
alarm_investigation_actions
alarm_ec2_actions
dashboard_variables
application_signals_services
service_level_objectives
log_group_tags
stale_log_groups
cloudwatch_omni_spaces
cloudwatch_omni_integrations
""".splitlines()

EXPECTED_HANDLERS = {
    "custom_ec2_cloudwatch_agent_check": "execute_ec2_cloudwatch_agent_check",
    "custom_lambda_json_logging_check": "execute_lambda_json_logging_check",
    "custom_ecs_task_log_check": "execute_ecs_task_log_check",
    "custom_eks_control_plane_logs_check": "execute_eks_control_plane_logs_check",
    "custom_field_indexes_per_log_group_check": "execute_field_indexes_per_log_group_check",
    "custom_eks_addons_check": "execute_eks_addons_check",
    "custom_ecs_container_insights_check": "execute_ecs_container_insights_check",
    "custom_lambda_insights_check": "execute_lambda_insights_check",
    "custom_metrics_namespaces_check": "execute_custom_metrics_namespaces_check",
    "custom_cloudwatch_alarms_check": "execute_cloudwatch_alarms_check",
    "custom_log_export_tasks_per_log_group_check": "execute_log_export_tasks_per_log_group_check",
    "custom_top_log_groups_retention_check": "execute_top_log_groups_retention_check",
    "custom_subscription_filters_coverage_check": "execute_subscription_filters_coverage_check",
    "custom_log_centralization_analysis_check": "execute_log_centralization_analysis_check",
    "custom_oam_links_and_sinks_check": "execute_oam_links_and_sinks_check",
    "custom_json_structured_logs_check": "execute_json_structured_logs_check",
    "custom_alarm_sns_configuration_check": "execute_alarm_sns_configuration_check",
    "custom_anomaly_detection_bands_check": "execute_anomaly_detection_bands_check",
    "custom_alarm_opsitem_actions_check": "execute_alarm_opsitem_actions_check",
    "custom_devops_agent_spaces_check": "execute_devops_agent_spaces_check",
    "custom_alarm_lambda_actions_check": "execute_alarm_lambda_actions_check",
    "custom_alarm_investigations_actions_check": "execute_alarm_investigations_actions_check",
    "custom_alarm_ec2_actions_check": "execute_alarm_ec2_actions_check",
    "custom_dashboard_variables_check": "execute_dashboard_variables_check",
    "custom_xray_service_graph_check": "execute_xray_service_graph_check",
    "custom_xray_sampling_rules_check": "execute_xray_sampling_rules_check",
    "custom_log_groups_categorization_check": "execute_log_groups_categorization_check",
    "custom_log_group_tags_check": "execute_log_group_tags_check",
    "custom_stale_log_groups_check": "execute_stale_log_groups_check",
    "custom_app_signals_list_services_check": "execute_app_signals_list_services_check",
    "custom_xray_custom_annotations_check": "execute_xray_custom_annotations_check",
    "custom_xray_insights_check": "execute_xray_insights_check",
    "custom_cloudwatch_omni_spaces_check": "execute_cloudwatch_omni_spaces_check",
    "custom_cloudwatch_omni_integrations_check": "execute_cloudwatch_omni_integrations_check",
}


def configured_assessment():
    assessment = ComprehensiveObservabilityAssessment()
    groups = {kind: [] for kind in ("EC2", "ECS", "Lambda", "EKS")}
    with (
        patch.object(
            assessment, "get_largest_log_groups_by_compute_type", return_value=groups
        ) as prefetch,
        contextlib.redirect_stdout(io.StringIO()),
    ):
        assessment.setup_discovery_checks()
    prefetch.assert_called_once_with()
    return assessment


class DiscoveryCatalogTests(unittest.TestCase):
    def test_specs_freeze_current_rows_and_stable_keys(self):
        expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
        actual = [
            {
                "id": spec.id,
                "name": spec.name,
                "category": spec.category,
                "command": spec.command,
            }
            for spec in CHECK_SPECS
        ]
        self.assertEqual(actual, expected)
        self.assertEqual([spec.key for spec in CHECK_SPECS], EXPECTED_KEYS)
        self.assertEqual(len(CHECK_SPECS_BY_ID), 52)
        self.assertEqual(len(CHECK_SPECS_BY_KEY), 52)
        for spec in CHECK_SPECS:
            self.assertIs(CHECK_SPECS_BY_ID[spec.id], spec)
            self.assertIs(CHECK_SPECS_BY_KEY[spec.key], spec)
        with self.assertRaises(FrozenInstanceError):
            CHECK_SPECS[0].key = "changed"
        with self.assertRaises(TypeError):
            CHECK_SPECS_BY_KEY["changed"] = CHECK_SPECS[0]

    def test_shared_category_memberships_keep_legacy_string(self):
        expected = {
            33: ("Dashboards", "Logs", "Metrics"),
            47: ("Metrics", "Traces"),
            48: ("Metrics", "Organization"),
        }
        for check_id, categories in expected.items():
            spec = CHECK_SPECS_BY_ID[check_id]
            self.assertEqual(spec.categories, categories)
            self.assertEqual(spec.category, ", ".join(categories))

    def test_setup_keeps_prefetch_and_existing_results(self):
        assessment = configured_assessment()
        check = assessment.results.discovery_checks[0]
        check.status = "success"
        extension_id = assessment.add_discovery_check("Extra", "Logs", "aws demo")
        self.assertEqual(extension_id, 53)
        with (
            patch.object(
                assessment,
                "get_largest_log_groups_by_compute_type",
                return_value={kind: [] for kind in ("EC2", "ECS", "Lambda", "EKS")},
            ) as prefetch,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            assessment.setup_discovery_checks()
        prefetch.assert_called_once_with()
        self.assertEqual(len(assessment.results.discovery_checks), 53)
        self.assertIs(assessment.results.discovery_checks[0], check)
        self.assertEqual(check.status, "success")
        self.assertEqual(assessment.discovery_check_counter, 53)

    def test_custom_registry_matches_legacy_mapping_and_catalog(self):
        self.assertEqual(dict(executor.CUSTOM_HANDLERS), EXPECTED_HANDLERS)
        self.assertEqual(
            set(executor.CUSTOM_HANDLERS),
            {
                spec.command
                for spec in CHECK_SPECS
                if spec.command.startswith("custom_")
            },
        )
        for method_name in executor.CUSTOM_HANDLERS.values():
            self.assertTrue(
                callable(getattr(ComprehensiveObservabilityAssessment, method_name))
            )
        with self.assertRaises(TypeError):
            executor.CUSTOM_HANDLERS["custom_new_check"] = "execute_new_check"
        with patch.object(executor, "CUSTOM_HANDLERS", {}):
            with self.assertRaisesRegex(ValueError, "handler mismatch"):
                executor._validate_custom_handlers()

    def test_every_custom_check_dispatches_without_cli_fallback(self):
        assessment = configured_assessment()
        with (
            patch.object(assessment, "run_aws_command") as cli,
            patch.object(assessment, "export_check_result_to_csv") as export,
            patch.object(
                assessment, "generate_detailed_evidence", return_value="evidence"
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            for spec in CHECK_SPECS:
                if not spec.command.startswith("custom_"):
                    continue
                check = assessment.results.discovery_checks[spec.id - 1]
                result = {"key": spec.key}
                method_name = EXPECTED_HANDLERS[spec.command]
                with patch.object(
                    assessment, method_name, return_value=result
                ) as handler:
                    assessment.execute_discovery_check(spec.id)
                handler.assert_called_once_with()
                self.assertIs(check.result, result)
                self.assertEqual(
                    (check.status, check.evidence), ("success", "evidence")
                )
                export.assert_called_with(check)
        cli.assert_not_called()

    def test_literal_cli_command_and_error_semantics(self):
        assessment = configured_assessment()
        cli_spec = CHECK_SPECS_BY_ID[18]
        cli_check = assessment.results.discovery_checks[cli_spec.id - 1]
        with (
            patch.object(assessment, "run_aws_command", return_value={}) as cli,
            patch.object(assessment, "export_check_result_to_csv") as export,
            patch.object(
                assessment, "generate_detailed_evidence", return_value="evidence"
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            assessment.execute_discovery_check(cli_spec.id)
        cli.assert_called_once_with(cli_spec.command)
        export.assert_called_once_with(cli_check)
        self.assertEqual(
            (cli_check.result, cli_check.status, cli_check.evidence),
            ({}, "success", "evidence"),
        )

        custom_spec = CHECK_SPECS_BY_ID[34]
        custom_check = assessment.results.discovery_checks[custom_spec.id - 1]
        with (
            patch.object(
                assessment, EXPECTED_HANDLERS[custom_spec.command], return_value=None
            ),
            patch.object(assessment, "run_aws_command") as cli,
            patch.object(assessment, "export_check_to_csv") as export_error,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            assessment.execute_discovery_check(custom_spec.id)
        cli.assert_not_called()
        export_error.assert_called_once_with(
            custom_check.name[:50],
            0,
            0,
            {"reason": "no result returned"},
            status="Unavailable",
        )
        self.assertIsNone(custom_check.result)
        self.assertEqual(custom_check.status, "error")
        self.assertIn("could not be evaluated", custom_check.evidence)

    def test_unknown_custom_command_fails_without_cli_execution(self):
        assessment = ComprehensiveObservabilityAssessment()
        check_id = assessment.add_discovery_check(
            "Unknown custom", "Logs", "custom_unknown_check"
        )
        with (
            patch.object(assessment, "run_aws_command") as cli,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            assessment.execute_discovery_check(check_id)
        cli.assert_not_called()
        check = assessment.results.discovery_checks[0]
        self.assertEqual(check.status, "error")
        self.assertIn("Unknown custom discovery command", check.evidence)


if __name__ == "__main__":
    unittest.main()
