# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json

from observability_assessment.text import plural


class AlarmsDiscoveryMixin:
    """Collect CloudWatch alarm and action configuration."""

    def _fetch_alarms(self):
        """Fetch metric and composite alarms, or None if either call fails."""
        metric_alarms_result = self.run_aws_command(
            "aws cloudwatch describe-alarms --alarm-types MetricAlarm --output json"
        )
        composite_alarms_result = self.run_aws_command(
            "aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json"
        )
        if metric_alarms_result is None or composite_alarms_result is None:
            return None
        return {
            "MetricAlarms": metric_alarms_result.get("MetricAlarms", []),
            "CompositeAlarms": composite_alarms_result.get("CompositeAlarms", []),
        }

    def execute_cloudwatch_alarms_check(self):
        """Custom check for CloudWatch alarms including both metric and composite alarms"""
        try:
            return self._fetch_alarms()
        except Exception:
            return None

    def execute_alarm_sns_configuration_check(self):
        """Check first 50 alarms for SNS topic configurations"""
        try:
            alarms = self._fetch_alarms()
            if alarms is None:
                return None

            # Combine and limit to first 50 alarms
            all_alarms = alarms["MetricAlarms"] + alarms["CompositeAlarms"]
            first_50_alarms = all_alarms[:50]

            alarms_with_sns = []
            alarms_without_sns = []

            for alarm in first_50_alarms:
                alarm_name = alarm.get("AlarmName", "Unknown")
                alarm_actions = alarm.get("AlarmActions", [])
                ok_actions = alarm.get("OKActions", [])
                insufficient_data_actions = alarm.get("InsufficientDataActions", [])

                # Check if any action is an SNS topic (ARN contains :sns:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                sns_topics = [action for action in all_actions if ":sns:" in action]

                if sns_topics:
                    alarms_with_sns.append(
                        {
                            "AlarmName": alarm_name,
                            "SNSTopics": sns_topics,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )
                else:
                    alarms_without_sns.append(
                        {
                            "AlarmName": alarm_name,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )

            return {
                "total_alarms_checked": len(first_50_alarms),
                "alarms_with_sns": len(alarms_with_sns),
                "alarms_without_sns": len(alarms_without_sns),
                "alarms_with_sns_details": alarms_with_sns,
                "alarms_without_sns_details": alarms_without_sns,
            }

        except Exception:
            return None

    def execute_anomaly_detection_bands_check(self):
        """Check for anomaly detection bands configured for metrics"""
        try:
            # Get anomaly detectors
            anomaly_detectors_result = self.run_aws_command(
                "aws cloudwatch describe-anomaly-detectors --anomaly-detector-types SINGLE_METRIC METRIC_MATH --output json"
            )
            if anomaly_detectors_result is None:
                return None
            anomaly_detectors = anomaly_detectors_result.get("AnomalyDetectors", [])

            bands_configured = []

            for detector in anomaly_detectors:
                # Top-level Namespace/MetricName/Dimensions are deprecated in
                # favor of SingleMetricAnomalyDetector; metric math detectors
                # carry MetricMathAnomalyDetector instead.
                single = detector.get("SingleMetricAnomalyDetector") or detector
                metric_math = detector.get("MetricMathAnomalyDetector")
                if metric_math:
                    namespace = "Metric math"
                    metric_name = ", ".join(
                        q.get("Expression") or q.get("Id", "Unknown")
                        for q in metric_math.get("MetricDataQueries", [])
                        if q.get("ReturnData", True)
                    )
                    dimensions = []
                else:
                    namespace = single.get("Namespace", "Unknown")
                    metric_name = single.get("MetricName", "Unknown")
                    dimensions = single.get("Dimensions", [])
                state = detector.get("StateValue", "Unknown")

                # Format dimensions for display
                dim_str = ", ".join(
                    [
                        f"{d.get('Name', 'Unknown')}={d.get('Value', 'Unknown')}"
                        for d in dimensions
                    ]
                )

                bands_configured.append(
                    {
                        "Namespace": namespace,
                        "MetricName": metric_name,
                        "Dimensions": dim_str,
                        "State": state,
                        "DimensionCount": len(dimensions),
                    }
                )

            return {
                "total_bands": len(bands_configured),
                "bands_details": bands_configured,
            }

        except Exception:
            return None

    def execute_alarm_opsitem_actions_check(self):
        """Check first 50 alarms for OpsItem creation actions"""
        try:
            alarms = self._fetch_alarms()
            if alarms is None:
                return None

            # Combine and limit to first 50 alarms
            all_alarms = alarms["MetricAlarms"] + alarms["CompositeAlarms"]
            first_50_alarms = all_alarms[:50]

            alarms_with_opsitem = []
            alarms_without_opsitem = []

            for alarm in first_50_alarms:
                alarm_name = alarm.get("AlarmName", "Unknown")
                alarm_actions = alarm.get("AlarmActions", [])
                ok_actions = alarm.get("OKActions", [])
                insufficient_data_actions = alarm.get("InsufficientDataActions", [])

                # Check if any action is an OpsItem action (ARN contains :opsitem:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                opsitem_actions = [
                    action for action in all_actions if ":opsitem:" in action
                ]

                if opsitem_actions:
                    alarms_with_opsitem.append(
                        {
                            "AlarmName": alarm_name,
                            "OpsItemActions": opsitem_actions,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )
                else:
                    alarms_without_opsitem.append(
                        {
                            "AlarmName": alarm_name,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )

            return {
                "total_alarms_checked": len(first_50_alarms),
                "alarms_with_opsitem": len(alarms_with_opsitem),
                "alarms_without_opsitem": len(alarms_without_opsitem),
                "alarms_with_opsitem_details": alarms_with_opsitem,
                "alarms_without_opsitem_details": alarms_without_opsitem,
            }

        except Exception:
            return None

    def execute_alarm_lambda_actions_check(self):
        """Check first 50 alarms for Lambda function invocation actions"""
        try:
            alarms = self._fetch_alarms()
            if alarms is None:
                return None

            # Combine and limit to first 50 alarms
            all_alarms = alarms["MetricAlarms"] + alarms["CompositeAlarms"]
            first_50_alarms = all_alarms[:50]

            alarms_with_lambda = []
            alarms_without_lambda = []

            for alarm in first_50_alarms:
                alarm_name = alarm.get("AlarmName", "Unknown")
                alarm_actions = alarm.get("AlarmActions", [])
                ok_actions = alarm.get("OKActions", [])
                insufficient_data_actions = alarm.get("InsufficientDataActions", [])

                # Check if any action is a Lambda function (ARN contains :lambda:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                lambda_actions = [
                    action for action in all_actions if ":lambda:" in action
                ]

                if lambda_actions:
                    alarms_with_lambda.append(
                        {
                            "AlarmName": alarm_name,
                            "LambdaActions": lambda_actions,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )
                else:
                    alarms_without_lambda.append(
                        {
                            "AlarmName": alarm_name,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )

            return {
                "total_alarms_checked": len(first_50_alarms),
                "alarms_with_lambda": len(alarms_with_lambda),
                "alarms_without_lambda": len(alarms_without_lambda),
                "alarms_with_lambda_details": alarms_with_lambda,
                "alarms_without_lambda_details": alarms_without_lambda,
            }

        except Exception:
            return None

    def execute_alarm_investigations_actions_check(self):
        """Check first 50 alarms for CloudWatch Investigations actions"""
        try:
            alarms = self._fetch_alarms()
            if alarms is None:
                return None

            # Combine and limit to first 50 alarms
            all_alarms = alarms["MetricAlarms"] + alarms["CompositeAlarms"]
            first_50_alarms = all_alarms[:50]

            alarms_with_investigations = []
            alarms_without_investigations = []

            for alarm in first_50_alarms:
                alarm_name = alarm.get("AlarmName", "Unknown")
                alarm_actions = alarm.get("AlarmActions", [])
                ok_actions = alarm.get("OKActions", [])
                insufficient_data_actions = alarm.get("InsufficientDataActions", [])

                # Check if any action is a CloudWatch Investigations action (ARN contains :aiops:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                investigations_actions = [
                    action for action in all_actions if ":aiops:" in action
                ]

                if investigations_actions:
                    alarms_with_investigations.append(
                        {
                            "AlarmName": alarm_name,
                            "InvestigationsActions": investigations_actions,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )
                else:
                    alarms_without_investigations.append(
                        {
                            "AlarmName": alarm_name,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )

            return {
                "total_alarms_checked": len(first_50_alarms),
                "alarms_with_investigations": len(alarms_with_investigations),
                "alarms_without_investigations": len(alarms_without_investigations),
                "alarms_with_investigations_details": alarms_with_investigations,
                "alarms_without_investigations_details": alarms_without_investigations,
            }

        except Exception:
            return None

    def execute_alarm_ec2_actions_check(self):
        """Check first 50 alarms for EC2 actions"""
        try:
            alarms = self._fetch_alarms()
            if alarms is None:
                return None

            # Combine and limit to first 50 alarms
            all_alarms = alarms["MetricAlarms"] + alarms["CompositeAlarms"]
            first_50_alarms = all_alarms[:50]

            alarms_with_ec2 = []
            alarms_without_ec2 = []

            for alarm in first_50_alarms:
                alarm_name = alarm.get("AlarmName", "Unknown")
                alarm_actions = alarm.get("AlarmActions", [])
                ok_actions = alarm.get("OKActions", [])
                insufficient_data_actions = alarm.get("InsufficientDataActions", [])

                # Check if any action is an EC2 action (ARN contains :ec2:)
                all_actions = alarm_actions + ok_actions + insufficient_data_actions
                ec2_actions = [action for action in all_actions if ":ec2:" in action]

                if ec2_actions:
                    alarms_with_ec2.append(
                        {
                            "AlarmName": alarm_name,
                            "EC2Actions": ec2_actions,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )
                else:
                    alarms_without_ec2.append(
                        {
                            "AlarmName": alarm_name,
                            "AlarmActions": alarm_actions,
                            "OKActions": ok_actions,
                            "InsufficientDataActions": insufficient_data_actions,
                        }
                    )

            return {
                "total_alarms_checked": len(first_50_alarms),
                "alarms_with_ec2": len(alarms_with_ec2),
                "alarms_without_ec2": len(alarms_without_ec2),
                "alarms_with_ec2_details": alarms_with_ec2,
                "alarms_without_ec2_details": alarms_without_ec2,
            }

        except Exception:
            return None

    def execute_dashboard_variables_check(self):
        """Check dashboards for dynamic variables and templating"""
        try:
            # Get list of dashboards
            dashboards_result = self.run_aws_command(
                "aws cloudwatch list-dashboards --output json"
            )
            if dashboards_result is None:
                return None
            dashboards = dashboards_result.get("DashboardEntries", [])

            dashboards_with_variables = []
            dashboards_without_variables = []
            dashboards_failed = []

            for dashboard in dashboards:
                dashboard_name = dashboard.get("DashboardName", "Unknown")

                try:
                    # Get dashboard body
                    dashboard_body_result = self.run_aws_command(
                        f"aws cloudwatch get-dashboard --dashboard-name {self._sanitize(dashboard_name)} --output json"
                    )
                    if dashboard_body_result is None:
                        dashboards_failed.append(dashboard_name)
                        continue
                    dashboard_body = dashboard_body_result.get("DashboardBody", "")

                    # Dashboard variables live in the body's top-level
                    # "variables" array. "${...}" also matches dynamic labels
                    # such as ${PROP(...)}, so it is not a variables signal.
                    try:
                        body = json.loads(dashboard_body) if dashboard_body else {}
                    except ValueError:
                        body = {}
                    variables = (
                        body.get("variables") if isinstance(body, dict) else None
                    )
                    has_variables = isinstance(variables, list) and bool(variables)
                    variable_indicators = (
                        [plural(len(variables), "variable")] if has_variables else []
                    )

                    if has_variables:
                        dashboards_with_variables.append(
                            {
                                "DashboardName": dashboard_name,
                                "VariableIndicators": variable_indicators,
                                "Size": dashboard.get("Size", 0),
                            }
                        )
                    else:
                        dashboards_without_variables.append(
                            {
                                "DashboardName": dashboard_name,
                                "Size": dashboard.get("Size", 0),
                            }
                        )

                except Exception:
                    # Unreadable dashboards are unknown, not "without variables"
                    dashboards_failed.append(dashboard_name)

            return {
                "total_dashboards": len(dashboards),
                "failed_lookups": len(dashboards_failed),
                "dashboards_with_variables": len(dashboards_with_variables),
                "dashboards_without_variables": len(dashboards_without_variables),
                "dashboards_with_variables_details": dashboards_with_variables,
                "dashboards_without_variables_details": dashboards_without_variables,
            }

        except Exception:
            return None
