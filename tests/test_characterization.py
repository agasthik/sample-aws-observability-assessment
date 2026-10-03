# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Characterize the public assessment contract before and after extraction.

All AWS activity is replaced with synthetic results. Import from the root
entrypoint because it remains the compatibility wrapper after extraction.
"""

import contextlib
import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from botocore.exceptions import ClientError

import observability_assessment_comprehensive as public


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent
ACCOUNT_A = "111111111111"
ACCOUNT_B = "222222222222"
ACCOUNT_FAILED = "333333333333"


def configured_assessment():
    assessment = public.ComprehensiveObservabilityAssessment()
    assessment.run_aws_command = Mock(return_value={})
    with contextlib.redirect_stdout(io.StringIO()):
        assessment.setup_discovery_checks()
        assessment.setup_assessment_questions()
    return assessment


def discovery(assessment, check_id):
    return next(
        check for check in assessment.results.discovery_checks if check.id == check_id
    )


def question(assessment, question_id):
    return next(
        check
        for check in assessment.results.assessment_checks
        if check.question_id == question_id
    )


@contextlib.contextmanager
def temporary_working_directory():
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as directory:
        try:
            os.chdir(directory)
            yield Path(directory)
        finally:
            os.chdir(previous)


class CatalogContractTests(unittest.TestCase):
    def test_static_catalog_matches_legacy_output(self):
        assessment = public.ComprehensiveObservabilityAssessment()
        assessment.run_aws_command = Mock(return_value={})
        with (
            patch.object(
                assessment,
                "add_discovery_check",
                wraps=assessment.add_discovery_check,
            ) as registrations,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            assessment.setup_discovery_checks()

        expected = json.loads(
            (FIXTURES / "discovery_catalog.json").read_text(encoding="utf-8")
        )
        actual = [
            {
                "id": check.id,
                "name": check.name,
                "category": check.category,
                "command": check.command,
            }
            for check in assessment.results.discovery_checks
        ]
        self.assertEqual(registrations.call_count, 0)
        self.assertEqual(len(actual), 52)
        self.assertEqual(actual, expected)
        self.assertEqual([check["id"] for check in actual], list(range(1, 53)))
        self.assertEqual(
            len({(check["name"], check["command"]) for check in actual}), 52
        )
        self.assertEqual(assessment.discovery_check_counter, 52)

    def test_duplicate_categories_merge_without_changing_id_or_order(self):
        assessment = public.ComprehensiveObservabilityAssessment()
        first = assessment.add_discovery_check("Shared", "Metrics", "aws demo")
        second = assessment.add_discovery_check("Shared", "Logs", "aws demo")
        third = assessment.add_discovery_check("Shared", "Logs", "aws demo")
        distinct = assessment.add_discovery_check("Shared", "Logs", "aws other")

        self.assertEqual((first, second, third, distinct), (1, 1, 1, 2))
        self.assertEqual(
            [
                (check.id, check.category)
                for check in assessment.results.discovery_checks
            ],
            [(1, "Logs, Metrics"), (2, "Logs")],
        )

    def test_question_metadata(self):
        assessment = public.ComprehensiveObservabilityAssessment()
        with contextlib.redirect_stdout(io.StringIO()):
            assessment.setup_assessment_questions()

        expected = json.loads(
            (FIXTURES / "question_catalog.json").read_text(encoding="utf-8")
        )
        actual = [
            {
                "question_id": check.question_id,
                "category": check.category,
                "question": check.question,
                "target_level": check.target_level,
                "maturity_descriptions": {
                    str(level): description
                    for level, description in check.maturity_descriptions.items()
                },
            }
            for check in assessment.results.assessment_checks
        ]
        self.assertEqual(len(actual), 17)
        self.assertEqual(actual, expected)
        self.assertEqual([check["question_id"] for check in actual], list(range(1, 18)))


class CliContractTests(unittest.TestCase):
    def test_help_exposes_single_and_multi_account_options_without_aws(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "observability_assessment_comprehensive.py"),
                "--help",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in (
            "--profile",
            "--region",
            "--role-arn",
            "--single-check",
            "--single-question",
            "--debug",
            "--accounts",
            "--ou",
            "--cross-account-role",
            "--max-workers",
        ):
            with self.subTest(option=option):
                self.assertIn(option, result.stdout)

    def test_codebuild_single_account_role_routes_to_assessment(self):
        from observability_assessment import cli

        role_arn = (
            f"arn:aws:iam::{ACCOUNT_A}:role/service-role/ObservabilityAssessmentRole"
        )
        argv = [
            "observability_assessment_comprehensive.py",
            "--region",
            "us-east-1",
            "--role-arn",
            role_arn,
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(cli, "ComprehensiveObservabilityAssessment") as constructor,
            patch.object(cli, "MultiAccountAssessment") as multi_constructor,
        ):
            cli.main()

        constructor.assert_called_once_with(
            profile=None, region="us-east-1", role_arn=role_arn
        )
        constructor.return_value.run_assessment.assert_called_once_with()
        multi_constructor.assert_not_called()

    def test_single_check_question_and_debug_route_to_assessment(self):
        import logging

        from observability_assessment import cli

        for option, method in (
            ("--single-check", "run_single_check"),
            ("--single-question", "run_single_question"),
        ):
            for check_id in (3, 0):
                with self.subTest(option=option, check_id=check_id):
                    argv = ["assessment", option, str(check_id), "--debug"]
                    with (
                        patch.object(sys, "argv", argv),
                        patch.object(
                            cli, "ComprehensiveObservabilityAssessment"
                        ) as constructor,
                        patch.object(
                            cli, "MultiAccountAssessment"
                        ) as multi_constructor,
                        patch.object(cli.logging, "basicConfig") as logging_config,
                    ):
                        cli.main()

                    getattr(constructor.return_value, method).assert_called_once_with(
                        check_id
                    )
                    constructor.return_value.run_assessment.assert_not_called()
                    multi_constructor.assert_not_called()
                    self.assertEqual(
                        logging_config.call_args.kwargs["level"], logging.DEBUG
                    )

    def test_failed_single_account_run_exits_non_zero(self):
        from observability_assessment import cli

        for option, method in (
            (["--single-check", "999"], "run_single_check"),
            (["--single-question", "99"], "run_single_question"),
            ([], "run_assessment"),
        ):
            with self.subTest(method=method):
                with (
                    patch.object(sys, "argv", ["assessment", *option]),
                    patch.object(
                        cli, "ComprehensiveObservabilityAssessment"
                    ) as constructor,
                    patch.object(cli.logging, "basicConfig"),
                ):
                    getattr(constructor.return_value, method).return_value = False
                    with self.assertRaises(SystemExit) as raised:
                        cli.main()
                self.assertEqual(raised.exception.code, 1)

    def test_full_assessment_aborts_when_identity_is_unavailable(self):
        assessment = public.ComprehensiveObservabilityAssessment()
        assessment.run_aws_command = Mock(return_value=None)
        assessment.execute_all_discovery_checks = Mock()
        assessment.generate_html_report = Mock()

        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertFalse(assessment.run_full_assessment())

        self.assertIn("Could not get AWS identity", stdout.getvalue())
        assessment.execute_all_discovery_checks.assert_not_called()
        assessment.generate_html_report.assert_not_called()

    def test_multi_account_rejects_zero_single_check(self):
        from observability_assessment import cli

        with (
            patch.object(
                sys,
                "argv",
                ["assessment", "--accounts", ACCOUNT_A, "--single-check", "0"],
            ),
            patch.object(cli, "MultiAccountAssessment") as constructor,
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as exit_status,
        ):
            cli.main()

        self.assertEqual(exit_status.exception.code, 1)
        constructor.assert_not_called()

    def test_codebuild_accounts_route_to_multi_account_assessment(self):
        from observability_assessment import cli

        argv = [
            "observability_assessment_comprehensive.py",
            "--region",
            "us-west-2",
            "--accounts",
            f"{ACCOUNT_A},{ACCOUNT_B}",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(cli, "ComprehensiveObservabilityAssessment") as constructor,
            patch.object(cli, "MultiAccountAssessment") as multi_constructor,
        ):
            cli.main()

        multi_constructor.assert_called_once_with(
            profile=None,
            region="us-west-2",
            accounts=[ACCOUNT_A, ACCOUNT_B],
            ou_ids=None,
            role_name="ObservabilityAssessmentRole",
            max_workers=5,
        )
        multi_constructor.return_value.run.assert_called_once_with()
        constructor.assert_not_called()

    def test_codebuild_ou_route_to_multi_account_assessment(self):
        from observability_assessment import cli

        argv = [
            "observability_assessment_comprehensive.py",
            "--region",
            "us-east-1",
            "--ou",
            "ou-root-1111,ou-child-2222",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(cli, "ComprehensiveObservabilityAssessment") as constructor,
            patch.object(cli, "MultiAccountAssessment") as multi_constructor,
        ):
            cli.main()

        multi_constructor.assert_called_once_with(
            profile=None,
            region="us-east-1",
            accounts=None,
            ou_ids=["ou-root-1111", "ou-child-2222"],
            role_name="ObservabilityAssessmentRole",
            max_workers=5,
        )
        multi_constructor.return_value.run.assert_called_once_with()
        constructor.assert_not_called()

    def test_multi_account_rejects_single_check_question_and_role_arn(self):
        from observability_assessment import cli

        for flags in (
            ["--accounts", ACCOUNT_A, "--single-check", "7"],
            ["--ou", "ou-root-1111", "--single-question", "3"],
            ["--accounts", ACCOUNT_A, "--role-arn", "arn:aws:iam::role"],
        ):
            with (
                self.subTest(flags=flags),
                patch.object(
                    sys, "argv", ["observability_assessment_comprehensive.py", *flags]
                ),
                patch.object(cli, "ComprehensiveObservabilityAssessment") as single,
                patch.object(cli, "MultiAccountAssessment") as multi,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as caught:
                    cli.main()
                self.assertEqual(caught.exception.code, 1)
                single.assert_not_called()
                multi.assert_not_called()


class RunnerContractTests(unittest.TestCase):
    def setUp(self):
        self.assessment = public.ComprehensiveObservabilityAssessment(
            profile="synthetic-profile", region="us-east-1"
        )

    @staticmethod
    def process(returncode=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(
            args=["aws"], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_successful_empty_output_is_empty_dict(self):
        with patch(
            "observability_assessment.aws.subprocess.run",
            return_value=self.process(stdout=" \n"),
        ) as run:
            self.assertEqual(
                self.assessment.run_aws_command(
                    "aws sts get-caller-identity --output json"
                ),
                {},
            )
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["aws", "--profile", "synthetic-profile", "sts"])
        self.assertEqual(argv[-4:], ["--region", "us-east-1", "--output", "json"])
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_valid_json_is_decoded(self):
        with patch(
            "observability_assessment.aws.subprocess.run",
            return_value=self.process(stdout='{"Items": []}'),
        ):
            self.assertEqual(
                self.assessment.run_aws_command("aws logs demo --output json"),
                {"Items": []},
            )

    def test_nonzero_exit_and_malformed_json_are_failures(self):
        cases = (
            self.process(returncode=254, stderr="AccessDenied"),
            self.process(stdout="{not-json"),
        )
        for process in cases:
            with (
                self.subTest(process=process),
                patch(
                    "observability_assessment.aws.subprocess.run", return_value=process
                ) as run,
            ):
                self.assertIsNone(
                    self.assessment.run_aws_command(
                        "aws logs demo --output json", max_retries=2
                    )
                )
                self.assertEqual(run.call_count, 1)

    def test_throttling_retries_then_succeeds(self):
        with (
            patch(
                "observability_assessment.aws.subprocess.run",
                side_effect=[
                    self.process(returncode=1, stderr="ThrottlingException"),
                    self.process(returncode=1, stderr="Rate exceeded"),
                    self.process(stdout='{"ok": true}'),
                ],
            ) as run,
            patch("observability_assessment.aws.time.sleep") as sleep,
        ):
            result = self.assessment.run_aws_command(
                "aws logs demo --output json", max_retries=2
            )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])

    def test_throttling_stops_after_retry_budget(self):
        with (
            patch(
                "observability_assessment.aws.subprocess.run",
                return_value=self.process(returncode=1, stderr="RequestLimitExceeded"),
            ) as run,
            patch("observability_assessment.aws.time.sleep") as sleep,
        ):
            self.assertIsNone(
                self.assessment.run_aws_command(
                    "aws logs demo --output json", max_retries=1
                )
            )
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_timeout_and_os_error_fail_without_retry(self):
        for error in (subprocess.TimeoutExpired("aws", 30), OSError("missing aws")):
            with (
                self.subTest(error=error),
                patch(
                    "observability_assessment.aws.subprocess.run", side_effect=error
                ) as run,
            ):
                self.assertIsNone(
                    self.assessment.run_aws_command(
                        "aws logs demo --output json", max_retries=3
                    )
                )
                self.assertEqual(run.call_count, 1)

    def test_empty_success_and_failure_have_different_check_status(self):
        assessment = public.ComprehensiveObservabilityAssessment()
        check_id = assessment.add_discovery_check(
            "Synthetic discovery", "Logs", "aws logs describe-log-groups --output json"
        )
        check = discovery(assessment, check_id)
        with (
            patch.object(assessment, "export_check_result_to_csv"),
            patch.object(assessment, "export_check_to_csv"),
            patch.object(
                assessment, "generate_detailed_evidence", return_value="evidence"
            ),
            patch.object(assessment, "run_aws_command", side_effect=[{}, None]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            assessment.execute_discovery_check(check_id)
            self.assertEqual((check.result, check.status), ({}, "success"))
            assessment.execute_discovery_check(check_id)
        self.assertIsNone(check.result)
        self.assertEqual(check.status, "error")
        self.assertIn("could not be evaluated", check.evidence)


class ScoringContractTests(unittest.TestCase):
    def test_logs_maturity_uses_lambda_logging_evidence(self):
        assessment = configured_assessment()
        target = question(assessment, 1)
        assessment.results.assessment_checks = [target]
        assessment.largest_log_groups = {"Lambda": ["/aws/lambda/orders"]}
        lambda_logs = discovery(assessment, 8)
        lambda_logs.status = "success"
        lambda_logs.result = {"json_logging_count": 1}

        assessment.assess_logs_maturity()

        self.assertEqual(target.current_level, 2)
        self.assertIn(lambda_logs.id, target.evidence_check_ids)
        self.assertIn("Lambda", target.explanation)

    def test_metrics_maturity_uses_ec2_detailed_monitoring_evidence(self):
        assessment = configured_assessment()
        target = question(assessment, 5)
        assessment.results.assessment_checks = [target]
        assessment.largest_log_groups = {"EC2": ["/ec2/orders"]}
        ec2_detailed = discovery(assessment, 18)
        ec2_detailed.result = [{"InstanceId": "i-synthetic"}]

        assessment.assess_metrics_maturity()

        self.assertEqual(target.current_level, 2)
        self.assertIn(ec2_detailed.id, target.evidence_check_ids)
        self.assertIn("EC2 detailed monitoring", target.explanation)

    def test_metrics_maturity_credits_enhanced_ecs_container_insights(self):
        assessment = configured_assessment()
        target = question(assessment, 5)
        assessment.results.assessment_checks = [target]
        assessment.largest_log_groups = {"ECS": ["/ecs/orders"]}
        # Clusters inherit "enhanced" from the account default (verified live).
        discovery(assessment, 20).result = {
            "clusters": [
                {"settings": [{"name": "containerInsights", "value": "enhanced"}]}
            ]
        }

        assessment.assess_metrics_maturity()

        self.assertIn("ECS Container Insights", target.explanation)

    def test_metrics_maturity_ignores_empty_ec2_reservations(self):
        assessment = configured_assessment()
        target = question(assessment, 5)
        assessment.results.assessment_checks = [target]
        assessment.largest_log_groups = {"EC2": ["/ec2/orders"]}
        ec2_detailed = discovery(assessment, 18)
        # One empty list per reservation: no instance has detailed monitoring.
        ec2_detailed.result = [[], []]

        assessment.assess_metrics_maturity()

        self.assertNotIn("EC2 detailed monitoring", target.explanation or "")

    def test_traces_maturity_uses_service_map_and_sampling_evidence(self):
        assessment = configured_assessment()
        target = question(assessment, 8)
        assessment.results.assessment_checks = [target]
        service_map = discovery(assessment, 26)
        sampling = discovery(assessment, 27)
        service_map.result = {"Services": [{"Name": "orders"}]}
        sampling.result = {"SamplingRuleRecords": [{"RuleName": "orders"}]}

        assessment.assess_traces_maturity()

        self.assertEqual(target.current_level, 2)
        self.assertIn(service_map.id, target.evidence_check_ids)
        self.assertIn(sampling.id, target.evidence_check_ids)
        self.assertIn("X-Ray service map", target.explanation)

    def test_alarm_maturity_uses_metric_alarms_and_sns_evidence(self):
        assessment = configured_assessment()
        target = question(assessment, 10)
        assessment.results.assessment_checks = [target]
        alarms = discovery(assessment, 34)
        sns_actions = discovery(assessment, 36)
        alarms.result = {"MetricAlarms": [{"AlarmName": "HighLatency"}]}
        sns_actions.result = {"alarms_with_sns": 1}

        assessment.assess_dashboards_alarms_maturity()

        self.assertEqual(target.current_level, 2)
        self.assertIn(alarms.id, target.evidence_check_ids)
        self.assertIn(sns_actions.id, target.evidence_check_ids)
        self.assertIn("SNS notifications", target.explanation)

    def test_alarm_maturity_credits_automated_alarm_actions(self):
        assessment = configured_assessment()
        target = question(assessment, 10)
        assessment.results.assessment_checks = [target]
        discovery(assessment, 34).result = {
            "MetricAlarms": [{"AlarmName": "HighLatency"}]
        }
        discovery(assessment, 37).result = {"total_bands": 1}
        opsitem = discovery(assessment, 41)
        lambda_actions = discovery(assessment, 43)
        ec2_actions = discovery(assessment, 45)
        opsitem.result = {"alarms_with_opsitem": 1}
        lambda_actions.result = {"alarms_with_lambda": 1}
        ec2_actions.result = {"alarms_with_ec2": 1}

        assessment.assess_dashboards_alarms_maturity()

        self.assertEqual(target.current_level, 3)
        self.assertIn(
            f"automated actions via Lambda (Check #{lambda_actions.id}), "
            f"EC2 (Check #{ec2_actions.id}), OpsCenter (Check #{opsitem.id})",
            target.explanation,
        )

    def test_slo_question_reaches_all_four_maturity_levels(self):
        assessment = configured_assessment()
        target = question(assessment, 13)
        assessment.results.assessment_checks = [target]
        slo = discovery(assessment, 48)
        app_signals = discovery(assessment, 47)
        alarms = discovery(assessment, 34)

        scenarios = (
            (None, None, None, 1),
            (None, {"Services": [{}]}, None, 2),
            ({"SloSummaries": [{}]}, {"Services": [{}]}, None, 3),
            (
                {"SloSummaries": [{}]},
                {"Services": [{}]},
                {"MetricAlarms": [{}]},
                4,
            ),
        )
        for slo_result, app_result, alarm_result, expected_level in scenarios:
            with self.subTest(level=expected_level):
                slo.result = slo_result
                app_signals.result = app_result
                alarms.result = alarm_result
                assessment.assess_organization_maturity()
                self.assertEqual(target.current_level, expected_level)
                self.assertEqual(target.evidence_check_ids, [48, 47, 34])

    def test_roi_question_reaches_governance_levels(self):
        assessment = configured_assessment()
        target = question(assessment, 17)
        assessment.results.assessment_checks = [target]
        dashboard = discovery(assessment, 33)
        alarms = discovery(assessment, 34)
        retention = discovery(assessment, 2)
        tags = discovery(assessment, 38)
        export = discovery(assessment, 13)
        composite = discovery(assessment, 35)
        slo = discovery(assessment, 48)

        assessment.assess_organization_maturity()
        self.assertEqual(target.current_level, 1)
        dashboard.result = {"DashboardEntries": [{}]}
        alarms.result = {"MetricAlarms": [{}]}
        assessment.assess_organization_maturity()
        self.assertEqual(target.current_level, 2)
        retention.result = {
            "groups_with_retention": 3,
            "top_log_groups": [{}, {}, {}, {}, {}],
        }
        tags.result = {"ResourceTagMappingList": [{}]}
        assessment.assess_organization_maturity()
        self.assertEqual(target.current_level, 3)
        retention.result["groups_with_retention"] = 4
        export.result = {"exported_log_groups": 1}
        composite.result = {"CompositeAlarms": [{}]}
        slo.result = {"SloSummaries": [{}]}
        assessment.assess_organization_maturity()
        self.assertEqual(target.current_level, 4)
        self.assertEqual(target.evidence_check_ids, [33, 34, 2, 38, 13, 35, 50, 48])


class ReportContractTests(unittest.TestCase):
    def test_csv_columns_percentage_and_account_scoped_filename(self):
        assessment = public.ComprehensiveObservabilityAssessment()
        assessment.results.account_id = ACCOUNT_A
        assessment.timestamp = "20300101_010203"
        with temporary_working_directory():
            assessment.export_check_to_csv(
                "Synthetic ratio", 2, 4, {"sample": ACCOUNT_A}
            )
            assessment.export_check_to_csv("Empty denominator", 0, 0)
            with open(assessment.csv_file, newline="", encoding="utf-8") as stream:
                rows = list(csv.reader(stream))

        self.assertTrue(assessment.csv_file.endswith(f"_{ACCOUNT_A}.csv"))
        self.assertEqual(
            rows[0],
            [
                "Check Name",
                "Found Count",
                "Total Count",
                "Percentage",
                "Details",
                "Status",
            ],
        )
        self.assertEqual(rows[1][:4], ["Synthetic ratio", "2", "4", "50.0%"])
        self.assertEqual(json.loads(rows[1][4]), {"sample": ACCOUNT_A})
        self.assertEqual(
            rows[2], ["Empty denominator", "0", "0", "0.0%", "", "Evaluated"]
        )

    def test_csv_formula_cells_are_neutralized_and_rows_stay_parseable(self):
        assessment = public.ComprehensiveObservabilityAssessment()
        assessment.results.account_id = ACCOUNT_A
        names = [
            "=1+1",
            "+SUM(1,1)",
            "-2+3",
            "@SUM(A1:A2)",
            "＝1+1",
            "  =1+1",
            "\t=1+1",
            "\r\n=1+1",
            'safe","=1+1',
            "Safe name",
        ]
        with temporary_working_directory():
            for name in names:
                assessment.export_check_to_csv(name, 1, 2, {"sample": "=1+1"})
            assessment.export_check_to_csv(
                "Status probe", 1, 2, {"sample": "=1+1"}, status="=1+1"
            )
            csv_text = Path(assessment.csv_file).read_text(encoding="utf-8")
            with open(assessment.csv_file, newline="", encoding="utf-8") as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(
            [row[0] for row in rows[1:]],
            [
                "\t=1+1",
                "\t+SUM(1,1)",
                "\t-2+3",
                "\t@SUM(A1:A2)",
                "\t＝1+1",
                "\t  =1+1",
                r"\t=1+1",
                r"\r\n=1+1",
                'safe","=1+1',
                "Safe name",
                "Status probe",
            ],
        )
        self.assertTrue(all(line.startswith('"') for line in csv_text.splitlines()))
        self.assertTrue(all(row[1:4] == ["1", "2", "50.0%"] for row in rows[1:]))
        self.assertTrue(
            all(json.loads(row[4]) == {"sample": "=1+1"} for row in rows[1:])
        )
        self.assertEqual(rows[-1][5], "\t=1+1")

    def test_html_contains_assessment_and_discovery_shape(self):
        assessment = configured_assessment()
        assessment.results.account_id = ACCOUNT_A
        assessment.results.user_arn = f"arn:aws:iam::{ACCOUNT_A}:user/synthetic"
        assessment.html_file = "assessment-result/synthetic.html"
        for scored in assessment.results.assessment_checks:
            scored.current_level, scored.assessed = 1, True
        question(assessment, 13).current_level = 3

        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                assessment.generate_html_report()
            html = Path(assessment.html_file).read_text(encoding="utf-8")

        self.assertEqual(assessment.results.overall_score, 19 / 17)
        self.assertEqual(assessment.results.maturity_level, "Reactive")
        self.assertEqual(assessment.results.timestamp, assessment.timestamp)
        payload_match = re.search(
            r'<script id="assessment-data" type="application/json">([^<]+)</script>',
            html,
        )
        self.assertIsNotNone(payload_match)
        payload = json.loads(payload_match.group(1))
        self.assertEqual(len(payload["questions"]), 17)
        self.assertEqual(len(payload["discovery"]), 52)
        self.assertEqual(payload["summary"]["overallScore"], 19 / 17)
        self.assertEqual(payload["meta"]["accountId"], ACCOUNT_A)
        for marker in (
            "<!DOCTYPE html>",
            "AWS Observability Assessment Report",
            'id="assessment-data"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, html)
        self.assertIn(
            "How do you use SLOs?",
            [item["question"] for item in payload["questions"]],
        )


class MultiAccountContractTests(unittest.TestCase):
    def test_explicit_account_discovery_filters_and_deduplicates(self):
        multi = object.__new__(public.MultiAccountAssessment)
        multi.explicit_accounts = [ACCOUNT_A, "invalid", ACCOUNT_A, ACCOUNT_B]
        multi.discovered_accounts = []
        multi.account_names = {}

        with (
            patch.object(multi, "_resolve_account_names") as resolve_names,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            multi.discover_accounts()

        self.assertEqual(multi.discovered_accounts, [ACCOUNT_A, ACCOUNT_B])
        resolve_names.assert_called_once_with([ACCOUNT_A, ACCOUNT_B])

    def test_ou_discovery_recurses_and_selects_active_accounts(self):
        from observability_assessment.orchestration import multi_account

        multi = object.__new__(public.MultiAccountAssessment)
        multi.explicit_accounts = None
        multi.ou_ids = ["ou-root"]
        multi.region = "us-west-2"
        multi.profile = None
        multi.discovered_accounts = []
        multi.account_names = {}
        multi.org_results = public.OrganizationAssessmentResults()

        accounts = {
            "ou-root": [
                {"Id": ACCOUNT_A, "Name": "Root", "Status": "ACTIVE"},
                {"Id": ACCOUNT_FAILED, "Name": "Inactive", "Status": "SUSPENDED"},
            ],
            "ou-child": [{"Id": ACCOUNT_B, "Name": "Child", "Status": "ACTIVE"}],
        }
        children = {
            "ou-root": [{"Id": "ou-child"}],
            "ou-child": [],
        }
        org_client = Mock()

        def paginator(operation):
            pages = accounts if operation == "list_accounts_for_parent" else children
            key = (
                "Accounts"
                if operation == "list_accounts_for_parent"
                else "OrganizationalUnits"
            )
            result = Mock()
            result.paginate.side_effect = lambda ParentId: [{key: pages[ParentId]}]
            return result

        org_client.get_paginator.side_effect = paginator
        session = Mock()
        session.client.return_value = org_client

        with patch.object(multi_account.boto3, "Session", return_value=session):
            multi.discover_accounts()

        self.assertEqual(multi.discovered_accounts, [ACCOUNT_A, ACCOUNT_B])
        self.assertEqual(multi.account_names, {ACCOUNT_A: "Root", ACCOUNT_B: "Child"})
        session.client.assert_called_once_with("organizations")
        self.assertEqual(org_client.get_paginator.call_count, 4)

    def test_ou_listing_failure_stops_incomplete_discovery(self):
        client = Mock()

        def paginator(operation):
            result = Mock()
            if operation == "list_accounts_for_parent":
                result.paginate.return_value = [
                    {"Accounts": [{"Id": ACCOUNT_A, "Status": "ACTIVE"}]}
                ]
            else:
                result.paginate.side_effect = RuntimeError("Access denied")
            return result

        client.get_paginator.side_effect = paginator
        with self.assertRaisesRegex(RuntimeError, "child OUs under ou-root"):
            public.MultiAccountAssessment._list_accounts_recursive(client, "ou-root")

        client.get_paginator.side_effect = RuntimeError("Access denied")
        with self.assertRaisesRegex(RuntimeError, "accounts under ou-root"):
            public.MultiAccountAssessment._list_accounts_recursive(client, "ou-root")

    def test_assess_account_uses_target_service_role(self):
        from observability_assessment.orchestration import multi_account

        multi = object.__new__(public.MultiAccountAssessment)
        multi.profile = "synthetic-profile"
        multi.region = "us-east-1"
        multi.role_name = "CustomAssessmentRole"
        multi.summary_report_filename = "organization_summary_synthetic.html"
        multi.management_account_id = ACCOUNT_A
        worker = Mock()
        worker.results = public.AssessmentResults(account_id=ACCOUNT_B)

        with patch.object(
            multi_account,
            "ComprehensiveObservabilityAssessment",
            return_value=worker,
        ) as constructor:
            result = multi.assess_account(ACCOUNT_B)

        self.assertEqual(result, (ACCOUNT_B, worker.results, None))
        constructor.assert_called_once_with(
            profile="synthetic-profile",
            region="us-east-1",
            role_arn=f"arn:aws:iam::{ACCOUNT_B}:role/service-role/CustomAssessmentRole",
            summary_report_filename="organization_summary_synthetic.html",
        )
        worker.run_full_assessment.assert_called_once_with()

    def test_management_account_falls_back_after_role_assumption_failure(self):
        from observability_assessment.orchestration import multi_account

        multi = object.__new__(public.MultiAccountAssessment)
        multi.profile = None
        multi.region = "us-west-2"
        multi.role_name = "ObservabilityAssessmentRole"
        multi.summary_report_filename = "organization_summary_synthetic.html"
        multi.management_account_id = ACCOUNT_A
        worker = Mock()
        worker.results = public.AssessmentResults(account_id=ACCOUNT_A)

        with patch.object(
            multi_account,
            "ComprehensiveObservabilityAssessment",
            side_effect=[
                ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    "AssumeRole",
                ),
                worker,
            ],
        ) as constructor:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = multi.assess_account(ACCOUNT_A)

        self.assertIn("falling back to the caller's own credentials", stdout.getvalue())
        self.assertIn("AccessDenied", stdout.getvalue())

        self.assertEqual(result, (ACCOUNT_A, worker.results, None))
        self.assertEqual(constructor.call_count, 2)
        self.assertEqual(
            constructor.call_args_list[0].kwargs["role_arn"],
            f"arn:aws:iam::{ACCOUNT_A}:role/service-role/ObservabilityAssessmentRole",
        )
        self.assertIsNone(constructor.call_args_list[1].kwargs["role_arn"])
        worker.run_full_assessment.assert_called_once_with()

    def test_management_account_does_not_fall_back_on_non_role_errors(self):
        from observability_assessment.orchestration import multi_account

        multi = object.__new__(public.MultiAccountAssessment)
        multi.profile = None
        multi.region = "us-west-2"
        multi.role_name = "ObservabilityAssessmentRole"
        multi.summary_report_filename = "organization_summary_synthetic.html"
        multi.management_account_id = ACCOUNT_A

        with patch.object(
            multi_account,
            "ComprehensiveObservabilityAssessment",
            side_effect=RuntimeError("unexpected"),
        ) as constructor:
            result = multi.assess_account(ACCOUNT_A)

        self.assertEqual(result, (ACCOUNT_A, None, "unexpected"))
        constructor.assert_called_once()

    def test_identity_failure_marks_account_failed(self):
        from observability_assessment.orchestration import multi_account

        multi = object.__new__(public.MultiAccountAssessment)
        multi.profile = None
        multi.region = "us-west-2"
        multi.role_name = "ObservabilityAssessmentRole"
        multi.summary_report_filename = "organization_summary_synthetic.html"
        multi.management_account_id = ACCOUNT_A
        worker = Mock()
        worker.run_full_assessment.return_value = False

        with patch.object(
            multi_account, "ComprehensiveObservabilityAssessment", return_value=worker
        ):
            result = multi.assess_account(ACCOUNT_B)

        self.assertEqual(result, (ACCOUNT_B, None, "Could not get AWS identity"))

    def test_other_account_reports_role_assumption_failure(self):
        from observability_assessment.orchestration import multi_account

        multi = object.__new__(public.MultiAccountAssessment)
        multi.profile = None
        multi.region = "us-west-2"
        multi.role_name = "ObservabilityAssessmentRole"
        multi.summary_report_filename = "organization_summary_synthetic.html"
        multi.management_account_id = ACCOUNT_A

        with patch.object(
            multi_account,
            "ComprehensiveObservabilityAssessment",
            side_effect=RuntimeError("assume role denied"),
        ) as constructor:
            result = multi.assess_account(ACCOUNT_B)

        self.assertEqual(result, (ACCOUNT_B, None, "assume role denied"))
        constructor.assert_called_once()

    def test_success_only_score_aggregation_and_summary_shape(self):
        multi = object.__new__(public.MultiAccountAssessment)
        multi.summary_report_filename = "organization_summary_synthetic.html"
        multi.org_results = public.OrganizationAssessmentResults(
            summary_report_filename=multi.summary_report_filename,
            account_results={
                ACCOUNT_A: public.AssessmentResults(
                    account_id=ACCOUNT_A,
                    timestamp="20300101_010203",
                    category_scores={"Logs": 1.0, "Metrics": 2.0},
                    overall_score=1.0,
                    maturity_level="Reactive",
                    assessment_checks=[
                        public.ObservabilityCheck(
                            1, "Logs", "Log collection", current_level=1, assessed=True
                        )
                    ],
                ),
                ACCOUNT_B: public.AssessmentResults(
                    account_id=ACCOUNT_B,
                    timestamp="20300101_010203",
                    category_scores={"Logs": 3.0, "Traces": 4.0},
                    overall_score=3.0,
                    maturity_level="Proactive",
                    assessment_checks=[
                        public.ObservabilityCheck(
                            1, "Logs", "Log collection", current_level=3, assessed=True
                        )
                    ],
                ),
            },
            account_names={ACCOUNT_A: "Synthetic A", ACCOUNT_B: "Synthetic B"},
            failed_accounts={ACCOUNT_FAILED: "Synthetic failure"},
        )

        multi.calculate_aggregated_scores()
        results = multi.org_results
        self.assertEqual(results.category_scores_avg["Logs"], 2.0)
        self.assertEqual(results.category_scores_min["Logs"], 1.0)
        self.assertEqual(results.category_scores_max["Logs"], 3.0)
        self.assertEqual(results.category_scores_avg["Metrics"], 2.0)
        self.assertEqual(results.category_scores_avg["Traces"], 4.0)
        self.assertEqual(
            (
                results.overall_score_avg,
                results.overall_score_min,
                results.overall_score_max,
            ),
            (2.0, 1.0, 3.0),
        )
        self.assertEqual(
            (results.maturity_level, results.best_maturity_level),
            ("Proactive", "Proactive"),
        )

        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                multi.generate_summary_report()
            html = Path("assessment-result", multi.summary_report_filename).read_text(
                encoding="utf-8"
            )

        payload_match = re.search(
            r'<script id="assessment-data" type="application/json">([^<]+)</script>',
            html,
        )
        self.assertIsNotNone(payload_match)
        payload = json.loads(payload_match.group(1))
        self.assertEqual(payload["reportType"], "organization")
        self.assertEqual(payload["summary"]["assessedAccounts"], 2)
        self.assertEqual(payload["summary"]["scoredAccounts"], 2)
        self.assertEqual(payload["summary"]["totalAccounts"], 3)
        self.assertEqual(payload["summary"]["averageScore"], 2.0)
        self.assertEqual(len(payload["accounts"]), 3)
        self.assertEqual(
            next(
                account for account in payload["accounts"] if account["id"] == ACCOUNT_A
            )["link"],
            f"observability_assessment_20300101_010203_{ACCOUNT_A}.html",
        )
        self.assertEqual(
            next(
                account
                for account in payload["accounts"]
                if account["id"] == ACCOUNT_FAILED
            )["error"],
            "Synthetic failure",
        )

    def test_organization_excludes_accounts_without_assessed_questions_from_scores(
        self,
    ):
        multi = object.__new__(public.MultiAccountAssessment)
        multi.org_results = public.OrganizationAssessmentResults(
            account_results={
                ACCOUNT_A: public.AssessmentResults(
                    account_id=ACCOUNT_A,
                    overall_score=2.0,
                    maturity_level="Proactive",
                    assessment_checks=[
                        public.ObservabilityCheck(
                            question_id=1,
                            category="Logs",
                            question="How are logs collected?",
                            current_level=2,
                            assessed=True,
                        )
                    ],
                ),
                ACCOUNT_B: public.AssessmentResults(
                    account_id=ACCOUNT_B,
                    overall_score=0.0,
                    maturity_level="Reactive",
                    assessment_checks=[
                        public.ObservabilityCheck(
                            question_id=1,
                            category="Logs",
                            question="How are logs collected?",
                            assessed=False,
                        )
                    ],
                ),
            },
        )

        multi.calculate_aggregated_scores()
        from observability_assessment.reporting.organization import organization_payload

        payload = organization_payload(multi.org_results)
        self.assertEqual(multi.org_results.overall_score_avg, 2.0)
        self.assertEqual(payload["summary"]["assessedAccounts"], 2)
        self.assertEqual(payload["summary"]["scoredAccounts"], 1)
        self.assertEqual(payload["summary"]["averageScore"], 2.0)
        unassessed = next(
            account for account in payload["accounts"] if account["id"] == ACCOUNT_B
        )
        self.assertIsNone(unassessed["score"])
        self.assertEqual(unassessed["maturity"], "Not assessed")

        unscored_multi = object.__new__(public.MultiAccountAssessment)
        unscored_multi.org_results = public.OrganizationAssessmentResults(
            account_results={ACCOUNT_B: multi.org_results.account_results[ACCOUNT_B]}
        )
        unscored_multi.calculate_aggregated_scores()
        unscored_payload = organization_payload(unscored_multi.org_results)
        self.assertIsNone(unscored_payload["summary"]["averageScore"])
        self.assertEqual(unscored_payload["summary"]["maturityLevel"], "Not assessed")


if __name__ == "__main__":
    unittest.main()
