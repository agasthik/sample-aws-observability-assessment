# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Failed AWS calls must surface as "unavailable", never as pass or fail."""

import contextlib
import csv
import io
import json
import re
import unittest
from pathlib import Path
from unittest.mock import Mock

from observability_assessment.discovery.executor import CUSTOM_HANDLERS
from observability_assessment.scoring.orchestration import average_level
from observability_assessment_comprehensive import ComprehensiveObservabilityAssessment

from test_characterization import (
    configured_assessment,
    discovery,
    question,
    temporary_working_directory,
)

LARGEST_LOG_GROUPS = {
    "EC2": ["/ec2/app"],
    "ECS": ["/ecs/app"],
    "Lambda": ["/aws/lambda/app"],
    "EKS": ["/aws/eks/app/cluster"],
}


def failing_assessment(largest_log_groups):
    assessment = ComprehensiveObservabilityAssessment(region="us-west-2")
    assessment.results.account_id = "111111111111"
    assessment.run_aws_command = Mock(return_value=None)
    assessment.largest_log_groups = largest_log_groups
    return assessment


class HandlerFailureTests(unittest.TestCase):
    def test_every_custom_handler_returns_none_when_aws_calls_fail(self):
        for largest in (None, LARGEST_LOG_GROUPS):
            for command, handler_name in CUSTOM_HANDLERS.items():
                with self.subTest(handler=handler_name, largest=bool(largest)):
                    assessment = failing_assessment(largest)
                    self.assertIsNone(getattr(assessment, handler_name)())

    def test_largest_log_groups_is_none_when_listing_fails(self):
        assessment = failing_assessment(None)
        self.assertIsNone(assessment.get_largest_log_groups_by_compute_type())

    def test_handler_exception_is_unavailable_not_zero(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        assessment.run_aws_command = Mock(side_effect=RuntimeError("boom"))
        self.assertIsNone(assessment.execute_cloudwatch_alarms_check())
        self.assertIsNone(assessment.execute_alarm_sns_configuration_check())

    def test_one_failed_alarm_listing_makes_alarm_checks_unavailable(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "CompositeAlarm" in command:
                return None
            return {"MetricAlarms": [{"AlarmName": "a"}]}

        assessment.run_aws_command = aws
        self.assertIsNone(assessment.execute_cloudwatch_alarms_check())
        self.assertIsNone(assessment.execute_alarm_ec2_actions_check())

    def test_sampling_rules_with_only_default_rule_is_a_real_answer(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        assessment.run_aws_command = Mock(
            return_value={
                "SamplingRuleRecords": [{"SamplingRule": {"RuleName": "Default"}}]
            }
        )
        self.assertEqual(
            assessment.execute_xray_sampling_rules_check(),
            {"SamplingRuleRecords": []},
        )

    def test_unreadable_log_group_is_not_reported_as_stale(self):
        assessment = failing_assessment({"Lambda": ["/aws/lambda/a", "/aws/lambda/b"]})

        def aws(command, *_args, **_kwargs):
            if "/aws/lambda/a" in command:
                return None
            return {"logStreams": [{"lastIngestionTime": 1}]}

        assessment.run_aws_command = aws
        result = assessment.execute_stale_log_groups_check()
        self.assertEqual(result["failed_lookups"], 1)
        self.assertEqual(result["total_checked"], 1)
        self.assertNotIn("/aws/lambda/a", [d["name"] for d in result["stale_details"]])

    def test_unreadable_dashboard_is_not_counted_without_variables(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        bodies = {"ops": None, "broken": {"DashboardBody": "{not json"}, "ok": {}}

        def aws(command, *_args, **_kwargs):
            if "list-dashboards" in command:
                return {"DashboardEntries": [{"DashboardName": n} for n in bodies]}
            return bodies[re.search(r"--dashboard-name '?(\w+)", command).group(1)]

        assessment.run_aws_command = aws
        result = assessment.execute_dashboard_variables_check()
        self.assertEqual(result["failed_lookups"], 2)
        self.assertEqual(result["dashboards_without_variables"], 1)

    def test_dashboard_check_is_unavailable_when_no_dashboard_is_readable(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "list-dashboards" in command:
                return {
                    "DashboardEntries": [{"DashboardName": "a"}, {"DashboardName": "b"}]
                }
            if "--dashboard-name a" in command:
                return {"DashboardBody": "{not json"}
            return None

        assessment.run_aws_command = aws
        self.assertIsNone(assessment.execute_dashboard_variables_check())

    def test_eks_addon_failures_are_excluded_from_denominator(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "list-clusters" in command:
                return {"clusters": ["a", "b"]}
            if "'a'" in command or " a " in command:
                return None
            if "describe-addon" in command:
                return {"addon": {"status": "ACTIVE"}}
            return {"addons": ["amazon-cloudwatch-observability"]}

        assessment.run_aws_command = aws
        result = assessment.execute_eks_addons_check()
        self.assertEqual(result["total_clusters"], 1)
        self.assertEqual(result["observability_clusters"], 1)
        self.assertEqual(result["failed_lookups"], 1)

    def test_eks_addon_requires_active_status_and_container_insights(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        addons = {
            "ok": {"status": "ACTIVE", "configurationValues": ""},
            "degraded": {"status": "DEGRADED"},
            "ci-off": {
                "status": "ACTIVE",
                "configurationValues": '{"containerInsights":{"enabled":false}}',
            },
            "otel": {
                "status": "ACTIVE",
                "configurationValues": '{"containerInsights":{"enabled":false},'
                '"otelContainerInsights":{"enabled":true}}',
            },
        }

        def aws(command, *_args, **_kwargs):
            if "list-clusters" in command:
                return {"clusters": list(addons)}
            if "list-addons" in command:
                return {"addons": ["amazon-cloudwatch-observability"]}
            name = re.search(r"--cluster-name '?([\w-]+)", command).group(1)
            return {"addon": addons[name]}

        assessment.run_aws_command = aws
        result = assessment.execute_eks_addons_check()
        self.assertEqual(result["clusters_with_observability"], ["ok", "otel"])
        self.assertEqual(
            [c["cluster"] for c in result["clusters_with_addon_issues"]],
            ["degraded", "ci-off"],
        )

    def test_eks_control_plane_all_types_is_per_cluster(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        types = {
            "a": ["api", "audit", "authenticator"],
            "b": ["controllerManager", "scheduler"],
        }

        def aws(command, *_args, **_kwargs):
            if "list-clusters" in command:
                return {"clusters": list(types)}
            name = re.search(r"--name '?([\w-]+)", command).group(1)
            return {
                "cluster": {
                    "logging": {
                        "clusterLogging": [{"enabled": True, "types": types[name]}]
                    }
                }
            }

        assessment.run_aws_command = aws
        result = assessment.execute_eks_control_plane_logs_check()
        self.assertEqual(result["enabled_types"], 5)
        self.assertEqual(result["clusters_all_enabled"], 0)
        self.assertFalse(result["all_types_enabled"])

    def test_lambda_native_json_log_format_is_counted(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "list-functions" in command:
                return {
                    "Functions": [
                        {
                            "FunctionName": f"text-{i}",
                            "LoggingConfig": {"LogFormat": "Text"},
                        }
                        for i in range(24)
                    ]
                    + [
                        {
                            "FunctionName": "native",
                            "LoggingConfig": {"LogFormat": "JSON"},
                        }
                    ]
                }
            raise AssertionError(f"unexpected per-function call: {command}")

        assessment.run_aws_command = aws
        result = assessment.execute_lambda_json_logging_check()
        # Every function is evaluated (no 20-function sample) from list-functions.
        self.assertEqual(result["functions_with_json"], ["native"])
        self.assertEqual(result["total_functions"], 25)

    def test_anomaly_bands_include_metric_math_detectors(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        commands = []

        def aws(command, *_args, **_kwargs):
            commands.append(command)
            return {
                "AnomalyDetectors": [
                    {
                        "SingleMetricAnomalyDetector": {
                            "Namespace": "AWS/EC2",
                            "MetricName": "CPUUtilization",
                            "Dimensions": [{"Name": "InstanceId", "Value": "i-1"}],
                        },
                        "StateValue": "TRAINED",
                    },
                    {
                        "MetricMathAnomalyDetector": {
                            "MetricDataQueries": [
                                {"Id": "m1", "ReturnData": False},
                                {"Id": "e1", "Expression": "m1 * 2"},
                            ]
                        },
                        "StateValue": "PENDING_TRAINING",
                    },
                ]
            }

        assessment.run_aws_command = aws
        result = assessment.execute_anomaly_detection_bands_check()
        self.assertIn("--anomaly-detector-types SINGLE_METRIC METRIC_MATH", commands[0])
        self.assertEqual(result["total_bands"], 2)
        self.assertEqual(result["bands_details"][0]["Namespace"], "AWS/EC2")
        self.assertEqual(result["bands_details"][1]["MetricName"], "m1 * 2")

    def test_dynamic_labels_are_not_dashboard_variables(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        bodies = {
            "labels": {"widgets": [{"properties": {"title": "${PROP('Dim.X')}"}}]},
            "vars": {"widgets": [], "variables": [{"id": "region"}]},
        }

        def aws(command, *_args, **_kwargs):
            if "list-dashboards" in command:
                return {"DashboardEntries": [{"DashboardName": n} for n in bodies]}
            name = re.search(r"--dashboard-name '?(\w+)", command).group(1)
            return {"DashboardBody": json.dumps(bodies[name])}

        assessment.run_aws_command = aws
        result = assessment.execute_dashboard_variables_check()
        self.assertEqual(
            [d["DashboardName"] for d in result["dashboards_with_variables_details"]],
            ["vars"],
        )

    def test_organization_member_is_not_labeled_management(self):
        for account_id, expected in (
            ("111111111111", "Organization Management Account"),
            ("222222222222", "Organization Member Account"),
        ):
            assessment = failing_assessment(LARGEST_LOG_GROUPS)
            assessment.results.account_id = account_id

            def aws(command, *_args, **_kwargs):
                if "describe-organization" in command:
                    return {"Organization": {"MasterAccountId": "111111111111"}}
                return {}

            assessment.run_aws_command = aws
            result = assessment.execute_log_centralization_analysis_check()
            self.assertEqual(result["organization_status"], expected)

    def test_standalone_account_is_not_in_organization(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "describe-organization" in command:
                assessment.last_aws_error = (
                    "An error occurred (AWSOrganizationsNotInUseException)"
                )
                return None
            assessment.last_aws_error = ""
            return {}

        assessment.run_aws_command = aws
        result = assessment.execute_log_centralization_analysis_check()
        self.assertEqual(result["organization_status"], "Not in Organization")

    def test_firehose_delivery_streams_are_paginated(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        listed = []

        def aws(command, *_args, **_kwargs):
            if "list-delivery-streams" in command:
                listed.append(command)
                if "--exclusive-start-delivery-stream-name" in command:
                    return {
                        "DeliveryStreamNames": ["s2"],
                        "HasMoreDeliveryStreams": False,
                    }
                return {"DeliveryStreamNames": ["s1"], "HasMoreDeliveryStreams": True}
            if "describe-delivery-stream" in command:
                return {"DeliveryStreamDescription": {"Destinations": []}}
            return {}

        assessment.run_aws_command = aws
        assessment.execute_log_centralization_analysis_check()
        self.assertEqual(len(listed), 2)
        self.assertIn("--exclusive-start-delivery-stream-name s1", listed[1])

    def test_ecs_log_driver_is_not_reported_as_json_logging(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "list-clusters" in command:
                return {"clusterArns": ["c"]}
            if "list-tasks" in command:
                return {"taskArns": ["t"]}
            if "describe-tasks" in command:
                return {"tasks": [{"taskArn": "t", "taskDefinitionArn": "td"}]}
            return {
                "taskDefinition": {
                    "family": "app",
                    "containerDefinitions": [
                        {"name": "app", "logConfiguration": {"logDriver": "awslogs"}}
                    ],
                }
            }

        assessment.run_aws_command = aws
        result = assessment.execute_ecs_task_log_check()
        self.assertEqual(result["logging_configured_count"], 1)
        self.assertNotIn("json_logging_count", result)

    def test_ecs_task_log_check_is_unavailable_when_no_task_is_readable(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "list-clusters" in command:
                return {"clusterArns": ["a", "b"]}
            if "list-tasks --cluster a" in command:
                return {"taskArns": ["t"]}
            return None

        assessment.run_aws_command = aws
        self.assertIsNone(assessment.execute_ecs_task_log_check())

    def test_ecs_clusters_without_running_tasks_are_still_evaluated(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

        def aws(command, *_args, **_kwargs):
            if "list-clusters" in command:
                return {"clusterArns": ["a"]}
            return {"taskArns": []}

        assessment.run_aws_command = aws
        result = assessment.execute_ecs_task_log_check()
        self.assertEqual(result["total_tasks"], 0)
        self.assertEqual(result["failed_lookups"], 0)

    def test_stale_log_group_probe_fetches_a_single_stream(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)
        commands = []

        def aws(command, *_args, **_kwargs):
            commands.append(command)
            return {"logStreams": []}

        assessment.run_aws_command = aws
        assessment.execute_stale_log_groups_check()
        probes = [c for c in commands if "describe-log-streams" in c]
        self.assertTrue(probes)
        for c in probes:
            self.assertIn("--max-items 1", c)
            self.assertNotIn("--limit", c)

    def test_ec2_failed_ssm_probe_is_not_agent_missing(self):
        assessment = failing_assessment(LARGEST_LOG_GROUPS)

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
            return None  # send-command fails

        assessment.run_aws_command = aws
        result = assessment.execute_ec2_cloudwatch_agent_check()
        self.assertEqual(result["failed_lookups"], 1)
        self.assertEqual(result["failed_probe_instances"], ["i-1"])


class ExecutorAndCsvTests(unittest.TestCase):
    def test_failed_check_writes_unavailable_csv_row(self):
        assessment = configured_assessment()
        assessment.results.account_id = "111111111111"
        assessment.timestamp = "20300101_000000"
        assessment.run_aws_command = Mock(return_value=None)
        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.execute_discovery_check(3)
            with open(assessment.csv_file, newline="") as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(discovery(assessment, 3).status, "error")
        self.assertEqual(rows[1][:4], ["Logs Insights Query Definitions", "", "", ""])
        self.assertEqual(rows[1][5], "Unavailable")

    def test_empty_success_writes_evaluated_csv_row(self):
        assessment = configured_assessment()
        assessment.results.account_id = "111111111111"
        assessment.timestamp = "20300101_000000"
        assessment.run_aws_command = Mock(return_value={})
        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.execute_discovery_check(3)
            with open(assessment.csv_file, newline="") as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(
            rows[1][:4], ["Logs Insights Query Definitions", "0", "1", "0.0%"]
        )
        self.assertEqual(rows[1][5], "Evaluated")

    def test_empty_success_list_is_csv_no(self):
        assessment = configured_assessment()
        assessment.results.account_id = "111111111111"
        assessment.timestamp = "20300101_000000"
        assessment.run_aws_command = Mock(return_value={"anomalyDetectors": []})
        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.execute_discovery_check(12)
            with open(assessment.csv_file, newline="") as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(rows[1][1:3], ["0", "1"])

    def test_inactive_transaction_search_is_csv_no(self):
        assessment = configured_assessment()
        assessment.results.account_id = "111111111111"
        assessment.timestamp = "20300101_000000"
        assessment.run_aws_command = Mock(
            return_value={"Destination": "XRay", "Status": "ACTIVE"}
        )
        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.execute_discovery_check(29)
            with open(assessment.csv_file, newline="") as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(rows[1][1:3], ["0", "1"])

    def test_csv_export_failure_keeps_successful_result(self):
        assessment = configured_assessment()
        assessment.run_aws_command = Mock(return_value={"queryDefinitions": []})
        assessment.export_check_result_to_csv = Mock(side_effect=OSError("disk full"))
        check = discovery(assessment, 3)
        with self.assertLogs("observability_assessment", "WARNING") as logs:
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.execute_discovery_check(check.id)

        self.assertEqual(check.status, "success")
        self.assertEqual(check.result, {"queryDefinitions": []})
        self.assertIn("disk full", logs.output[0])

    def test_partial_result_is_flagged_in_evidence(self):
        assessment = configured_assessment()
        check = discovery(assessment, 11)  # EKS add-on check
        assessment.execute_eks_addons_check = Mock(
            return_value={
                "total_clusters": 1,
                "observability_clusters": 0,
                "failed_lookups": 2,
            }
        )
        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.execute_discovery_check(check.id)
        self.assertEqual(check.status, "success")
        self.assertIn("Partial data", check.evidence)


class ScoringAvailabilityTests(unittest.TestCase):
    def errored_question(self, question_id):
        assessment = configured_assessment()
        with contextlib.redirect_stdout(io.StringIO()):
            assessment.assess_all_categories()
        target = question(assessment, question_id)
        for check_id in target.evidence_check_ids:
            check = discovery(assessment, check_id)
            check.status = "error"
            check.result = None
        return assessment, target

    def test_question_with_all_evidence_errored_is_not_assessed(self):
        assessment, target = self.errored_question(4)
        for check in assessment.results.discovery_checks:
            if check.id not in target.evidence_check_ids:
                check.status = "success"
        assessment.assess_all_categories()

        self.assertFalse(target.assessed)
        self.assertEqual(
            sorted(target.unavailable_check_ids), sorted(target.evidence_check_ids)
        )
        self.assertIn("Not assessed", target.explanation)

    def test_not_assessed_questions_are_excluded_from_scores(self):
        assessment = configured_assessment()
        for check in assessment.results.discovery_checks:
            check.status = "success"
        assessment.assess_all_categories()
        logs = [q for q in assessment.results.assessment_checks if q.category == "Logs"]

        # A not-assessed question's level does not move the category average.
        logs[0].assessed = False
        logs[0].current_level = 4
        others = logs[1:]
        self.assertEqual(
            average_level(logs),
            sum(q.current_level for q in others) / len(others),
        )

        # Every evidence check erroring removes all questions from the average.
        for check in assessment.results.discovery_checks:
            check.status = "error"
            check.result = None
        assessment.assess_all_categories()
        self.assertTrue(
            all(not q.assessed for q in assessment.results.assessment_checks)
        )
        self.assertEqual(assessment.results.category_scores, {})
        self.assertIsNone(assessment.compute_overall_score())

    def test_no_assessed_questions_show_na_in_report_and_console(self):
        from observability_assessment.reporting.cloudscape_bridge import (
            assessment_payload,
        )

        assessment = configured_assessment()
        for check in assessment.results.discovery_checks:
            check.status = "error"
            check.result = None
        assessment.assess_all_categories()
        output = io.StringIO()
        with temporary_working_directory() as directory:
            assessment.html_file = str(directory / "assessment-result" / "empty.html")
            assessment.generate_html_report()
            with contextlib.redirect_stdout(output):
                assessment.print_assessment_summary()
            self.assertTrue(Path(assessment.html_file).is_file())

        summary = assessment_payload(assessment)["summary"]
        self.assertIsNone(assessment.results.overall_score)
        self.assertEqual(assessment.results.maturity_level, "Not assessed")
        self.assertIsNone(summary["overallScore"])
        self.assertEqual(summary["maturityLevel"], "Not assessed")
        self.assertIn("Overall Score:   N/A", output.getvalue())
        self.assertRegex(output.getvalue(), r"Maturity Level:\s+Not assessed")

    def test_partially_errored_question_keeps_level_and_flags_checks(self):
        assessment = configured_assessment()
        for check in assessment.results.discovery_checks:
            check.status = "success"
        alarms = discovery(assessment, 34)
        alarms.status = "error"
        alarms.result = None
        assessment.assess_all_categories()

        target = question(assessment, 10)
        self.assertTrue(target.assessed)
        self.assertIn(alarms.id, target.unavailable_check_ids)

    def test_q1_does_not_credit_successful_zero_coverage(self):
        assessment = configured_assessment()
        target = question(assessment, 1)
        assessment.results.assessment_checks = [target]
        assessment.largest_log_groups = {"Lambda": ["/aws/lambda/orders"]}
        lambda_logs = discovery(assessment, 8)
        lambda_logs.status = "success"
        lambda_logs.result = {"json_logging_count": 0, "total_functions": 3}

        assessment.assess_logs_maturity()

        self.assertEqual(target.current_level, 1)
        self.assertNotIn("Lambda", target.explanation)

    def test_q1_tolerates_unavailable_log_group_listing(self):
        assessment = configured_assessment()
        assessment.largest_log_groups = None
        assessment.assess_logs_maturity()
        self.assertEqual(question(assessment, 1).current_level, 1)


class ReportAvailabilityTests(unittest.TestCase):
    def test_html_shows_unavailable_checks_and_not_assessed_questions(self):
        assessment = configured_assessment()
        assessment.results.account_id = "111111111111"
        assessment.html_file = "assessment-result/synthetic.html"
        for check in assessment.results.discovery_checks:
            check.status = "success"
        assessment.assess_all_categories()
        target = question(assessment, 4)
        for check_id in target.evidence_check_ids:
            discovery(assessment, check_id).status = "error"
        assessment.assess_all_categories()

        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.generate_html_report()
            html = Path(assessment.html_file).read_text(encoding="utf-8")

        match = re.search(
            r'<script id="assessment-data" type="application/json">([^<]+)</script>',
            html,
        )
        self.assertIsNotNone(match)
        payload = json.loads(match.group(1))
        self.assertGreater(payload["summary"]["discoveryUnavailable"], 0)
        self.assertEqual(payload["summary"]["questionsAssessed"], 16)
        self.assertEqual(len(payload["questions"]), 17)
        self.assertFalse(
            next(item for item in payload["questions"] if item["id"] == 4)["assessed"]
        )


if __name__ == "__main__":
    unittest.main()
