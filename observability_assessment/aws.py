# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""AWS CLI execution, role assumption, and SSM polling helpers."""

import json
import logging
import os
import shlex
import subprocess
import time

import boto3

logger = logging.getLogger("observability_assessment")


class AwsRunner:
    """Run AWS CLI commands with the assessment's current AWS configuration."""

    def __init__(self, profile=None, region="us-west-2", env_override=None):
        self.profile = profile
        self.region = region
        self.env_override = env_override
        # Why the last command failed (stderr, timeout, or launch error), so
        # callers can tell an expected "not in use" error apart from an access
        # or transport failure and report the cause.
        self.last_error = ""

    def run(self, command, max_retries=3):
        """Execute AWS CLI command and return result, with retry on throttling."""
        # Only rewrite the leading "aws " so quoted arguments are left intact.
        if self.profile and command.startswith("aws "):
            command = f"aws --profile {shlex.quote(self.profile)} " + command[4:]

        if "--region" not in command:
            command = command.replace(
                " --output", f" --region {shlex.quote(self.region)} --output"
            )

        for attempt in range(max_retries + 1):
            try:
                # Commands are tokenized and run without a shell. Shell syntax in
                # quoted arguments (e.g. SSM RunShellScript commands) is passed
                # through verbatim and executed remotely, never locally.
                result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
                    shlex.split(command),
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=self.env_override,
                )  # nosec B603
                if result.returncode == 0:
                    if not result.stdout.strip():
                        return {}
                    try:
                        return json.loads(result.stdout)
                    except json.JSONDecodeError as e:
                        self.last_error = f"Could not parse JSON output: {e}"
                        logger.warning(
                            "Could not parse JSON output from command '%s': %s",
                            command,
                            e,
                        )
                        return None
                if (
                    attempt < max_retries
                    and result.stderr
                    and any(
                        t in result.stderr
                        for t in (
                            "Throttling",
                            "Rate exceeded",
                            "RequestLimitExceeded",
                            "TooManyRequestsException",
                        )
                    )
                ):
                    time.sleep(2**attempt)  # nosemgrep: arbitrary-sleep
                    continue
                # Non-zero exit that is not a retryable throttle: log why it failed
                # so it is not silently indistinguishable from an empty result.
                self.last_error = result.stderr or ""
                logger.debug(
                    "Command failed (exit %s): '%s' -- %s",
                    result.returncode,
                    command,
                    (result.stderr or "").strip()[:500],
                )
                return None
            except subprocess.TimeoutExpired:
                self.last_error = "Command timed out after 30s"
                logger.warning("Command timed out after 30s: '%s'", command)
                return None
            except (OSError, ValueError) as e:
                self.last_error = f"Could not run the AWS CLI: {e}"
                logger.warning("Failed to execute command '%s': %s", command, e)
                return None


class AwsMixin:
    """Requires ``profile``, ``region``, and ``env_override`` on ``self``."""

    def _assume_role(self, role_arn):
        """Assume IAM role and set env vars for all subprocess AWS CLI calls"""
        session_kwargs = {"region_name": self.region}
        if self.profile:
            session_kwargs["profile_name"] = self.profile
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="ObservabilityAssessment"
        )["Credentials"]
        self.env_override = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
        }
        # Clear profile since we're using assumed role creds
        self.profile = None

    def run_aws_command(self, command, max_retries=3):
        """Execute an AWS CLI command through the configured runner."""
        runner = AwsRunner(self.profile, self.region, self.env_override)
        result = runner.run(command, max_retries)
        self.last_aws_error = runner.last_error
        return result

    @staticmethod
    def _sanitize(value: str) -> str:
        """Sanitize a value for safe interpolation into AWS CLI commands."""
        return shlex.quote(str(value))

    def _poll_ssm_command(
        self,
        command_id: str,
        instance_id: str,
        max_attempts: int = 12,
        interval: float = 5.0,
    ):
        """Poll SSM for command completion instead of arbitrary sleep.

        Run Command delivery routinely takes tens of seconds, so this waits
        up to about a minute before treating the probe as failed.
        """
        for _ in range(max_attempts):
            result = self.run_aws_command(
                f"aws ssm get-command-invocation --command-id {self._sanitize(command_id)} --instance-id {self._sanitize(instance_id)} --output json"
            )
            if result and result.get("Status") in (
                "Success",
                "Failed",
                "Cancelled",
                "TimedOut",
            ):
                return result
            time.sleep(interval)  # nosemgrep: arbitrary-sleep
        return None
