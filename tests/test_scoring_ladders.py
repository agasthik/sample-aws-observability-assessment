# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Level ladders for scoring, the EC2 agent probe parser, and CSV branches."""

import contextlib
import csv
import io
import unittest
from unittest.mock import Mock

from observability_assessment.models import DiscoveryCheck

from test_characterization import (
    configured_assessment,
    discovery,
    question,
    temporary_working_directory,
)

ALL_COMPUTE = {
    "EC2": ["/ec2/app"],
    "Lambda": ["/aws/lambda/app"],
    "ECS": ["/ecs/app"],
    "EKS": ["/aws/eks/app/cluster"],
}


class LevelLadderTests(unittest.TestCase):
    def assert_ladder(self, question_id, assess, scenarios, largest_log_groups=None):
        """Score each scenario ({check_id: result}) from a clean slate."""
        for label, results, expected_level in scenarios:
            with self.subTest(scenario=label):
                assessment = configured_assessment()
                assessment.largest_log_groups = largest_log_groups
                target = question(assessment, question_id)
                assessment.results.assessment_checks = [target]
                for check_id, result in results.items():
                    check = discovery(assessment, check_id)
                    check.result = result
                    check.status = "success"
                getattr(assessment, assess)()
                self.assertEqual(target.current_level, expected_level)

    def test_q1_log_collection_ladder_and_coverage_gates(self):
        ec2 = {7: {"logging_configured_count": 1}}
        lambda_json = {8: {"json_logging_count": 1}}
        eks = {10: {"enabled_types": 5}}
        centralized = {14: {"centralization_patterns": ["cross-account"]}}
        anomaly = {12: {"anomalyDetectors": [{}]}}
        half = {**ec2, **eks}  # 2 of 4 compute types
        three_quarters = {**ec2, **lambda_json, **eks}  # 3 of 4, JSON via Lambda

        self.assert_ladder(
            1,
            "assess_logs_maturity",
            (
                ("no signals", {}, 1),
                ("log groups only", {1: {"total_log_groups": 3}}, 1),
                ("one compute type", ec2, 1),
                ("half coverage", half, 2),
                (
                    "half coverage blocks L3",
                    {**half, 16: {"json_groups": 1}, **centralized},
                    2,
                ),
                (
                    "half coverage blocks L4",
                    {**half, 16: {"json_groups": 1}, **centralized, **anomaly},
                    2,
                ),
                ("75% coverage without centralization", three_quarters, 2),
                ("75% coverage centralized", {**three_quarters, **centralized}, 3),
                (
                    "75% coverage with anomaly detection",
                    {**three_quarters, **centralized, **anomaly},
                    4,
                ),
                (
                    "75% coverage with EKS add-on",
                    {
                        **three_quarters,
                        **centralized,
                        11: {"observability_clusters": 1},
                    },
                    4,
                ),
                (
                    "OAM link counts as centralization",
                    {**three_quarters, 15: {"links_count": 1}, **anomaly},
                    4,
                ),
            ),
            largest_log_groups=ALL_COMPUTE,
        )

    def test_q1_failed_compute_check_is_not_coverage(self):
        assessment = configured_assessment()
        assessment.largest_log_groups = {"EC2": ["/ec2/app"]}
        target = question(assessment, 1)
        assessment.results.assessment_checks = [target]
        ec2 = discovery(assessment, 7)
        ec2.result = {"logging_configured_count": 1}
        ec2.status = "error"

        assessment.assess_logs_maturity()

        self.assertEqual(target.current_level, 1)
        self.assertNotIn("CloudWatch agent configured", target.explanation)

    def test_q4_retention_ladder_and_ratio_gates(self):
        def retention(count):
            return {2: {"groups_with_retention": count, "top_log_groups": [{}] * 4}}

        export = {13: {"exported_log_groups": 1}}
        tags = {49: {"total_tagged_log_groups": 1}}
        self.assert_ladder(
            4,
            "assess_logs_maturity",
            (
                ("no retention", retention(0), 1),
                ("25% retention", retention(1), 1),
                ("25% retention blocks L3", {**retention(1), **export}, 1),
                ("50% retention", retention(2), 2),
                ("50% retention with export", {**retention(2), **export}, 3),
                (
                    "50% retention blocks L4",
                    {**retention(2), **export, **tags},
                    3,
                ),
                (
                    "subscription filters count as archival",
                    {**retention(2), 6: {"groups_with_subscription_filters": 1}},
                    3,
                ),
                (
                    "75% retention archived and tagged",
                    {**retention(3), **export, **tags},
                    4,
                ),
                ("75% retention needs archival for L4", {**retention(3), **tags}, 2),
            ),
        )

    def test_q10_alarm_ladder(self):
        alarms = {34: {"MetricAlarms": [{"AlarmName": "HighLatency"}]}}
        self.assert_ladder(
            10,
            "assess_dashboards_alarms_maturity",
            (
                ("no alarms", {}, 1),
                ("metric alarms only", alarms, 1),
                ("SNS notifications", {**alarms, 36: {"alarms_with_sns": 1}}, 2),
                ("anomaly detection", {**alarms, 37: {"total_bands": 1}}, 3),
                ("composite alarms", {35: {"CompositeAlarms": [{}]}}, 4),
                (
                    "composite and anomaly",
                    {
                        **alarms,
                        35: {"CompositeAlarms": [{}]},
                        37: {"total_bands": 1},
                    },
                    4,
                ),
            ),
        )

    def test_q11_dashboard_ladder(self):
        def dashboards(count):
            return {33: {"DashboardEntries": [{}] * count}}

        self.assert_ladder(
            11,
            "assess_dashboards_alarms_maturity",
            (
                ("no dashboards", {}, 1),
                ("two dashboards", dashboards(2), 1),
                ("three dashboards", dashboards(3), 2),
                (
                    "dashboard variables",
                    {**dashboards(1), 46: {"dashboards_with_variables": 1}},
                    3,
                ),
                ("Application Signals", {**dashboards(1), 47: {"Services": [{}]}}, 4),
                ("Application Signals without dashboards", {47: {"Services": [{}]}}, 1),
            ),
        )

    def test_q12_adaptive_threshold_ladder(self):
        self.assert_ladder(
            12,
            "assess_dashboards_alarms_maturity",
            (
                ("no alarms", {}, 1),
                (
                    "static thresholds",
                    {34: {"MetricAlarms": [{"EvaluationPeriods": 1}]}},
                    1,
                ),
                (
                    "sustained breach",
                    {34: {"MetricAlarms": [{"EvaluationPeriods": 3}]}},
                    2,
                ),
                (
                    "datapoints to alarm",
                    {34: {"MetricAlarms": [{"DatapointsToAlarm": 2}]}},
                    2,
                ),
                ("anomaly detection", {37: {"total_bands": 1}}, 3),
                (
                    "anomaly with DevOps Agent",
                    {37: {"total_bands": 1}, 42: {"total_spaces": 1}},
                    4,
                ),
                (
                    "anomaly with Investigations",
                    {37: {"total_bands": 1}, 44: {"alarms_with_investigations": 1}},
                    4,
                ),
                ("DevOps Agent alone", {42: {"total_spaces": 1}}, 1),
            ),
        )

    def test_q15_end_user_monitoring_ladder(self):
        self.assert_ladder(
            15,
            "assess_organization_maturity",
            (
                ("no monitoring", {}, 1),
                ("scheduled canary", {39: {"Canaries": [{"RunConfig": {}}]}}, 2),
                (
                    "canary with tracing",
                    {39: {"Canaries": [{"RunConfig": {"ActiveTracing": True}}]}},
                    3,
                ),
                ("RUM", {40: {"AppMonitorSummaries": [{}]}}, 4),
            ),
        )


class Ec2AgentProbeTests(unittest.TestCase):
    def probe(self, stdout):
        assessment = configured_assessment()

        def aws(command, *_args, **_kwargs):
            if "describe-instances" in command:
                return {
                    "Reservations": [
                        {
                            "Instances": [
                                {"InstanceId": "i-1", "State": {"Name": "running"}}
                            ]
                        }
                    ]
                }
            if "describe-instance-information" in command:
                return {"InstanceInformationList": [{"InstanceId": "i-1"}]}
            if "send-command" in command:
                command_id = "config" if "log_group_name" in command else "probe"
                return {"Command": {"CommandId": command_id}}
            return {}

        outputs = {"probe": stdout, "config": "1\n"}
        assessment.run_aws_command = aws
        assessment._poll_ssm_command = Mock(
            side_effect=lambda command_id, _instance: {
                "Status": "Success",
                "StandardOutputContent": outputs[command_id],
            }
        )
        return assessment.execute_ec2_cloudwatch_agent_check()

    def test_running_agent_signals_count(self):
        for label, stdout in (
            ("process running", "PROCESS_RUNNING\nSERVICE_NOT_ACTIVE\n0\n"),
            ("lone process count", "PROCESS_NOT_RUNNING\nSERVICE_NOT_ACTIVE\n2\n"),
            ("systemd active", "PROCESS_NOT_RUNNING\nactive\n0\n"),
        ):
            with self.subTest(label):
                result = self.probe(stdout)
                self.assertEqual(result["cw_agent_instances"], ["i-1"])
                self.assertEqual(result["logging_configured_count"], 1)

    def test_stopped_agent_signals_do_not_count(self):
        for label, stdout in (
            ("service not active", "PROCESS_NOT_RUNNING\nSERVICE_NOT_ACTIVE\n0\n"),
            ("systemd inactive", "PROCESS_NOT_RUNNING\ninactive\n0\n"),
        ):
            with self.subTest(label):
                result = self.probe(stdout)
                self.assertEqual(result["cw_agent_instances"], [])
                self.assertEqual(result["logging_configured_count"], 0)
                self.assertEqual(result["failed_lookups"], 0)


class CsvBranchTests(unittest.TestCase):
    def rows(self, check_id, result, name="Synthetic check"):
        assessment = configured_assessment()
        assessment.results.account_id = "111111111111"
        assessment.timestamp = "20300101_000000"
        check = (
            discovery(assessment, check_id)
            if check_id <= len(assessment.results.discovery_checks)
            else DiscoveryCheck(check_id, name, "Organization", "custom_synthetic")
        )
        check.result = result
        with temporary_working_directory():
            assessment.export_check_result_to_csv(check)
            if not assessment.csv_file:
                return []
            with open(assessment.csv_file, newline="") as stream:
                return list(csv.reader(stream))[1:]

    def test_omni_spaces_counts_active_of_total(self):
        rows = self.rows(
            51,
            {"active_spaces": 1, "total_spaces": 2, "has_organization_domain": True},
        )
        self.assertEqual(
            rows,
            [
                [
                    "CloudWatch Omni Spaces",
                    "1",
                    "2",
                    "50.0%",
                    '{"organization_domain": true}',
                    "Evaluated",
                ]
            ],
        )

    def test_omni_integrations_counts_active_of_total(self):
        rows = self.rows(
            52,
            {
                "active_integrations": 0,
                "total_integrations": 0,
                "active_by_type": {},
            },
        )
        self.assertEqual(
            rows, [["CloudWatch Omni Integrations", "0", "1", "0.0%", "", "Evaluated"]]
        )
        partial = self.rows(
            52,
            {
                "active_integrations": 1,
                "total_integrations": 1,
                "active_by_type": {"slack": 1},
                "failed_lookups": 1,
            },
        )
        self.assertEqual(
            partial[0][1:], ["1", "1", "100.0%", '{"slack": 1}', "Partial"]
        )

    def test_generic_handler_is_binary_found_count(self):
        found = self.rows(25, {"MetricStreams": [{}]})
        empty = self.rows(25, {})
        self.assertEqual(found[0][1:4], ["1", "1", "100.0%"])
        self.assertEqual(empty[0][1:4], ["0", "1", "0.0%"])
        self.assertEqual(found[0][0], empty[0][0])

    def test_check_beyond_catalog_writes_no_row(self):
        assessment = configured_assessment()
        self.assertEqual(len(assessment.results.discovery_checks), 52)
        self.assertEqual(self.rows(53, {"anything": 1}), [])

    def test_executor_skips_csv_for_check_beyond_catalog(self):
        assessment = configured_assessment()
        extra = DiscoveryCheck(53, "Synthetic", "Organization", "aws synthetic")
        assessment.results.discovery_checks.append(extra)
        assessment.run_aws_command = Mock(return_value={"anything": 1})
        assessment.export_check_result_to_csv = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            assessment.execute_discovery_check(53)
        self.assertEqual(extra.status, "success")
        assessment.export_check_result_to_csv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
