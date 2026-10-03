# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Focused contracts for the concrete AWS CLI runner and its compatibility mixin."""

import subprocess
import unittest
from unittest.mock import call, patch

from observability_assessment.aws import AwsMixin, AwsRunner


class ConfiguredAwsMixin(AwsMixin):
    def __init__(self, profile=None, region="us-east-1", env_override=None):
        self.profile = profile
        self.region = region
        self.env_override = env_override


class AwsRunnerTests(unittest.TestCase):
    @staticmethod
    def process(returncode=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(
            args=["aws"], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def test_direct_run_injects_profile_and_region_with_env(self):
        env = {"AWS_SESSION_TOKEN": "synthetic"}
        runner = AwsRunner("test-profile", "eu-west-1", env)
        with patch(
            "observability_assessment.aws.subprocess.run",
            return_value=self.process(stdout='{"Items": []}'),
        ) as execute:
            self.assertEqual(runner.run("aws logs demo --output json"), {"Items": []})

        execute.assert_called_once_with(
            [
                "aws",
                "--profile",
                "test-profile",
                "logs",
                "demo",
                "--region",
                "eu-west-1",
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def test_shell_syntax_is_never_run_locally_and_keeps_existing_region(self):
        runner = AwsRunner(region="us-east-1")
        command = (
            "aws ssm send-command --region ap-south-1 "
            "--parameters 'commands=[\"ps aux | grep agent && echo ok\"]' --output json"
        )
        with patch(
            "observability_assessment.aws.subprocess.run",
            return_value=self.process(stdout=" \n"),
        ) as execute:
            self.assertEqual(runner.run(command), {})

        execute.assert_called_once_with(
            [
                "aws",
                "ssm",
                "send-command",
                "--region",
                "ap-south-1",
                "--parameters",
                'commands=["ps aux | grep agent && echo ok"]',
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=None,
        )

    def test_direct_run_retries_throttle_and_distinguishes_failure(self):
        runner = AwsRunner(region="us-east-1")
        with (
            patch(
                "observability_assessment.aws.subprocess.run",
                side_effect=[
                    self.process(returncode=1, stderr="TooManyRequestsException"),
                    self.process(returncode=2, stderr="AccessDenied"),
                ],
            ) as execute,
            patch("observability_assessment.aws.time.sleep") as sleep,
        ):
            self.assertIsNone(runner.run("aws logs demo --output json", max_retries=2))

        self.assertEqual(execute.call_count, 2)
        self.assertEqual(sleep.call_args_list, [call(1)])

    def test_mixin_delegates_with_current_configuration_and_retry_budget(self):
        mixin = ConfiguredAwsMixin("first", "us-east-1")
        with patch.object(AwsRunner, "run", autospec=True, return_value={}) as run:
            self.assertEqual(
                mixin.run_aws_command("aws sts demo --output json", max_retries=1),
                {},
            )
            first_runner = run.call_args.args[0]
            self.assertEqual(
                (first_runner.profile, first_runner.region, first_runner.env_override),
                ("first", "us-east-1", None),
            )

            mixin.profile = None
            mixin.region = "eu-west-1"
            mixin.env_override = {"AWS_SESSION_TOKEN": "assumed"}
            mixin.run_aws_command("aws sts demo --output json", max_retries=4)
            second_runner = run.call_args.args[0]

        self.assertIsNot(first_runner, second_runner)
        self.assertEqual(
            (second_runner.profile, second_runner.region, second_runner.env_override),
            (None, "eu-west-1", {"AWS_SESSION_TOKEN": "assumed"}),
        )
        self.assertEqual(run.call_args.args[1:], ("aws sts demo --output json", 4))

    def test_assume_role_updates_next_runner_and_helpers_remain_callable(self):
        mixin = ConfiguredAwsMixin("first", "us-east-1")
        credentials = {
            "AccessKeyId": "key",
            "SecretAccessKey": "secret",  # pragma: allowlist secret
            "SessionToken": "token",
        }
        with patch("observability_assessment.aws.boto3.Session") as session:
            session.return_value.client.return_value.assume_role.return_value = {
                "Credentials": credentials
            }
            mixin._assume_role("arn:aws:iam::111111111111:role/test")

        session.assert_called_once_with(region_name="us-east-1", profile_name="first")
        self.assertIsNone(mixin.profile)
        self.assertEqual(mixin.env_override["AWS_SESSION_TOKEN"], "token")
        with patch(
            "observability_assessment.aws.subprocess.run",
            return_value=self.process(stdout="{}"),
        ) as execute:
            self.assertEqual(mixin.run_aws_command("aws sts demo --output json"), {})
        self.assertNotIn("--profile", execute.call_args.args[0])
        self.assertEqual(execute.call_args.kwargs["env"], mixin.env_override)

        self.assertEqual(mixin._sanitize("one two"), "'one two'")
        with patch.object(
            mixin, "run_aws_command", return_value={"Status": "Success"}
        ) as run:
            self.assertEqual(
                mixin._poll_ssm_command("command id", "instance id"),
                {"Status": "Success"},
            )
        self.assertIn("'command id'", run.call_args.args[0])
        self.assertIn("'instance id'", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
