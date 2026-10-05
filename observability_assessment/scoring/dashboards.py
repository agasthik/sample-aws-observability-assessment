# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Assessment scoring for dashboards."""

from observability_assessment.text import plural


class DashboardsScoringMixin:
    """Scoring methods that operate on ``self.results``."""

    def assess_dashboards_alarms_maturity(self):
        """Assess dashboards and alarms maturity based on discovery checks"""
        dashboard_checks = [
            c
            for c in self.results.assessment_checks
            if c.category == "Dashboards & Alerting"
        ]

        for check in dashboard_checks:
            if check.question_id == 10:  # How do you use alarms?
                alarms_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch alarms configured for your resources?"
                    ),
                    None,
                )
                composite_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use composite alarms to reduce alarm noise?"
                    ),
                    None,
                )
                sns_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "Do your alarms send notifications to SNS topics?"
                    ),
                    None,
                )
                anomaly_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use anomaly detection models for adaptive alarming?"
                    ),
                    None,
                )
                investigations_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you configured CloudWatch Investigations actions for any alarms?"
                    ),
                    None,
                )
                opsitem_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have any Systems Manager OpsCenter actions configured with your alarms?"
                    ),
                    None,
                )
                lambda_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have any Lambda actions configured with your alarms?"
                    ),
                    None,
                )
                ec2_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have any EC2 actions configured with your alarms?"
                    ),
                    None,
                )

                all_checks = [
                    alarms_check,
                    composite_check,
                    sns_check,
                    anomaly_check,
                    investigations_check,
                    opsitem_check,
                    lambda_check,
                    ec2_check,
                ]
                check.evidence_check_ids = [c.id for c in all_checks if c]

                has_basic_alarms = (
                    alarms_check
                    and isinstance(alarms_check.result, dict)
                    and alarms_check.result.get("MetricAlarms")
                )
                has_composite = (
                    composite_check
                    and isinstance(composite_check.result, dict)
                    and composite_check.result.get("CompositeAlarms")
                )
                has_anomaly = (
                    anomaly_check
                    and isinstance(anomaly_check.result, dict)
                    and anomaly_check.result.get("total_bands", 0) > 0
                )
                has_sns = (
                    sns_check
                    and isinstance(sns_check.result, dict)
                    and sns_check.result.get("alarms_with_sns", 0) > 0
                )
                has_investigations = (
                    investigations_check
                    and isinstance(investigations_check.result, dict)
                    and investigations_check.result.get("alarms_with_investigations", 0)
                    > 0
                )
                has_opsitem = (
                    opsitem_check
                    and isinstance(opsitem_check.result, dict)
                    and opsitem_check.result.get("alarms_with_opsitem", 0) > 0
                )
                has_lambda_actions = (
                    lambda_check
                    and isinstance(lambda_check.result, dict)
                    and lambda_check.result.get("alarms_with_lambda", 0) > 0
                )
                has_ec2_actions = (
                    ec2_check
                    and isinstance(ec2_check.result, dict)
                    and ec2_check.result.get("alarms_with_ec2", 0) > 0
                )
                has_automated_actions = (
                    has_opsitem
                    or has_lambda_actions
                    or has_ec2_actions
                    or has_investigations
                )

                # Analyze alarm names/descriptions for priority indicators
                import re

                priority_pattern = re.compile(
                    r"\b(P[1-4]|Sev[1-5]|Critical|High|Medium|Low|Urgent)\b",
                    re.IGNORECASE,
                )
                priority_alarms = 0
                if has_basic_alarms:
                    for a in alarms_check.result.get("MetricAlarms", []):
                        text = (
                            f"{a.get('AlarmName', '')} {a.get('AlarmDescription', '')}"
                        )
                        if priority_pattern.search(text):
                            priority_alarms += 1
                has_priority = priority_alarms > 0

                if has_composite and has_anomaly:
                    composite_count = len(
                        composite_check.result.get("CompositeAlarms", [])
                    )
                    anomaly_count = anomaly_check.result.get("total_bands", 0)
                    metric_count = (
                        len(alarms_check.result.get("MetricAlarms", []))
                        if has_basic_alarms
                        else 0
                    )
                    extras = []
                    if has_investigations:
                        extras.append(
                            f"Investigations (Check #{investigations_check.id})"
                        )
                    if has_opsitem:
                        extras.append(f"OpsCenter (Check #{opsitem_check.id})")
                    extra_str = (
                        f", integrated with {', '.join(extras)}" if extras else ""
                    )
                    check.current_level = 4
                    check.explanation = f"Advanced alarm strategy with {plural(composite_count, 'composite alarm')} (Check #{composite_check.id}) aggregating {plural(metric_count, 'metric alarm')} (Check #{alarms_check.id}) with {plural(anomaly_count, 'anomaly detector')} (Check #{anomaly_check.id}){extra_str}. Composite alarms create summarized health indicators reducing alarm noise, while anomaly detection accounts for seasonal patterns."
                elif has_composite:
                    composite_count = len(
                        composite_check.result.get("CompositeAlarms", [])
                    )
                    metric_count = (
                        len(alarms_check.result.get("MetricAlarms", []))
                        if has_basic_alarms
                        else 0
                    )
                    check.current_level = 4
                    check.explanation = f"Advanced alarm strategy with {plural(composite_count, 'composite alarm')} (Check #{composite_check.id}) aggregating {plural(metric_count, 'metric alarm')} (Check #{alarms_check.id if alarms_check else 'N/A'}). This creates summarized health indicators reducing alarm noise and enabling actions at an aggregated application level."
                elif has_anomaly and has_basic_alarms:
                    anomaly_count = anomaly_check.result.get("total_bands", 0)
                    alarm_count = len(alarms_check.result.get("MetricAlarms", []))
                    extras = []
                    if has_automated_actions:
                        action_parts = []
                        if has_lambda_actions:
                            action_parts.append(f"Lambda (Check #{lambda_check.id})")
                        if has_ec2_actions:
                            action_parts.append(f"EC2 (Check #{ec2_check.id})")
                        if has_opsitem:
                            action_parts.append(
                                f"OpsCenter (Check #{opsitem_check.id})"
                            )
                        extras.append(
                            f"automated actions via {', '.join(action_parts)}"
                        )
                    check.current_level = 3
                    check.explanation = f"Actionable alerting with {plural(anomaly_count, 'anomaly detector')} (Check #{anomaly_check.id}) complementing {plural(alarm_count, 'alarm')} (Check #{alarms_check.id}){' with ' + extras[0] if extras else ''}. ML-driven anomaly detection accounts for hourly, daily, and weekly patterns in metrics."
                elif has_basic_alarms and has_sns:
                    alarm_count = len(alarms_check.result.get("MetricAlarms", []))
                    sns_count = sns_check.result.get("alarms_with_sns", 0)
                    priority_str = (
                        f" {plural(priority_alarms, 'alarm')} {'includes' if priority_alarms == 1 else 'include'} priority indicators."
                        if has_priority
                        else ""
                    )
                    check.current_level = 2
                    check.explanation = f"Structured alerting with {plural(alarm_count, 'alarm')} (Check #{alarms_check.id}), {sns_count} configured with SNS notifications (Check #{sns_check.id}).{priority_str} This enables understanding of urgency and customer impact for operational issues."
                elif has_basic_alarms:
                    alarm_count = len(alarms_check.result.get("MetricAlarms", []))
                    check.current_level = 1
                    check.explanation = f"Basic alerting with {plural(alarm_count, 'alarm')} (Check #{alarms_check.id}) but limited notification configuration. Alarms trigger when metrics meet thresholds but lack SNS notification integration for operator awareness."
                else:
                    check.current_level = 1
                    check.explanation = "No alerting infrastructure detected. Limited ability to proactively notify operators when metrics meet alarm triggers."

            elif check.question_id == 11:  # How do you use dashboards?
                dashboards_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch dashboards for visualizing metrics and logs?"
                        and "Dashboards" in c.category
                    ),
                    None,
                )
                variables_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "Do you have dashboards configured with variables?"
                    ),
                    None,
                )
                app_signals_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use CloudWatch Application Signals to monitor application services?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [dashboards_check, variables_check, app_signals_check]
                    if c
                ]

                has_dashboards = (
                    dashboards_check
                    and dashboards_check.result
                    and dashboards_check.result.get("DashboardEntries")
                )
                has_variables = (
                    variables_check
                    and variables_check.result
                    and variables_check.result.get("dashboards_with_variables", 0) > 0
                )
                has_app_signals = (
                    app_signals_check
                    and app_signals_check.result
                    and app_signals_check.result.get("Services")
                )

                if has_dashboards:
                    dashboard_count = len(
                        dashboards_check.result.get("DashboardEntries", [])
                    )
                    dashboards_with_vars = (
                        variables_check.result.get("dashboards_with_variables", 0)
                        if variables_check and variables_check.result
                        else 0
                    )

                    # Level 4: Automatic dynamic visualizations
                    if has_app_signals:
                        service_count = len(
                            app_signals_check.result.get("Services", [])
                        )
                        check.current_level = 4
                        check.explanation = f"Automatically created dynamic visualizations with Application Signals monitoring {plural(service_count, 'service')} (Check #{app_signals_check.id}), which auto-generates service dashboards relevant to application health and performance. Additionally, {plural(dashboard_count, 'custom dashboard')} {'provides' if dashboard_count == 1 else 'provide'} operational visibility (Check #{dashboards_check.id}). This saves time and cost by automatically creating visualizations that contain only information relevant to issues."

                    # Level 3: Flexible dashboards with variables
                    elif has_variables:
                        check.current_level = 3
                        check.explanation = f"Flexible dashboards with dynamic content: {dashboards_with_vars} out of {plural(dashboard_count, 'dashboard')} {'is' if dashboards_with_vars == 1 else 'are'} configured with dynamic variables/input fields (Checks #{dashboards_check.id}, #{variables_check.id}). These dashboards can quickly display different content in multiple widgets depending on input field values (e.g., selecting different resources, time ranges, or grouping dimensions), enabling easier correlation and anomaly detection across services and contexts."

                    # Level 2: Single pane of glass
                    elif dashboard_count >= 3:
                        check.current_level = 2
                        check.explanation = f"Single pane of glass with {plural(dashboard_count, 'CloudWatch dashboard')} (Check #{dashboards_check.id}) providing visibility into various data sources. Multiple dashboards enable faster communication flow during operational events with well-defined visualization criteria. To reach Level 3, consider adding dynamic variables to dashboards for flexible, context-aware visualizations."

                    # Level 1: Basic monitoring
                    else:
                        check.current_level = 1
                        check.explanation = f"Basic resource monitoring with {plural(dashboard_count, 'dashboard')} (Check #{dashboards_check.id}). Limited dashboard count suggests primarily basic resource monitoring. To improve, create additional dashboards covering different services and operational aspects, and consider adding dynamic variables for flexible visualizations."
                else:
                    check.current_level = 1
                    check.explanation = "No dashboards detected. Limited or no dashboard usage for operational visibility. Create CloudWatch dashboards to visualize metrics, logs, and alarms for better operational awareness."

            elif check.question_id == 12:  # How adaptive are your alarm thresholds?
                anomaly_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use anomaly detection models for adaptive alarming?"
                    ),
                    None,
                )
                alarms_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch alarms configured for your resources?"
                    ),
                    None,
                )
                devops_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"
                    ),
                    None,
                )
                investigations_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you configured CloudWatch Investigations actions for any alarms?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [
                        anomaly_check,
                        alarms_check,
                        devops_check,
                        investigations_check,
                    ]
                    if c
                ]

                has_anomaly = (
                    anomaly_check
                    and anomaly_check.result
                    and anomaly_check.result.get("total_bands", 0) > 0
                )
                has_alarms = (
                    alarms_check
                    and alarms_check.result
                    and alarms_check.result.get("MetricAlarms")
                )
                has_devops = (
                    devops_check
                    and isinstance(devops_check.result, dict)
                    and devops_check.result.get("total_spaces", 0) > 0
                )
                has_investigations = (
                    investigations_check
                    and isinstance(investigations_check.result, dict)
                    and investigations_check.result.get("alarms_with_investigations", 0)
                    > 0
                )
                has_ai_analysis = has_devops or has_investigations

                if has_anomaly and has_ai_analysis:
                    anomaly_count = anomaly_check.result.get("total_bands", 0)
                    extras = []
                    if has_devops:
                        extras.append(f"AWS DevOps Agent (Check #{devops_check.id})")
                    if has_investigations:
                        extras.append(
                            f"Investigations (Check #{investigations_check.id})"
                        )
                    check.current_level = 4
                    check.explanation = f"Fully adaptive thresholds with {plural(anomaly_count, 'ML-based anomaly detector')} (Check #{anomaly_check.id}) and {', '.join(extras)} for continuous analysis. The system determines normal baselines, surfaces anomalies with minimal user intervention, and accounts for seasonality and trend changes automatically."
                elif has_anomaly:
                    anomaly_count = anomaly_check.result.get("total_bands", 0)
                    check.current_level = 3
                    check.explanation = f"Anomaly-based alerting with {plural(anomaly_count, 'anomaly detector')} (Check #{anomaly_check.id}) that {'triggers' if anomaly_count == 1 else 'trigger'} when metrics exhibit anomalous behavior. The ML model analyzes past metric data and creates expected value bands accounting for hourly, daily, and weekly patterns. Consider adding AWS DevOps Agent or Investigations for continuous automated analysis."
                elif has_alarms:
                    alarms = alarms_check.result.get("MetricAlarms", [])
                    time_based_alarms = [
                        a
                        for a in alarms
                        if a.get("EvaluationPeriods", 1) > 1
                        or a.get("DatapointsToAlarm", 1) > 1
                    ]

                    if time_based_alarms:
                        check.current_level = 2
                        check.explanation = f"Time-based alarm thresholds with {len(time_based_alarms)} out of {plural(len(alarms), 'alarm')} configured for sustained threshold breaches (Check #{alarms_check.id}). This reduces false positives by requiring metrics to exceed thresholds for a period of time before triggering."
                    else:
                        check.current_level = 1
                        check.explanation = f"Static alarm thresholds with {plural(len(alarms), 'alarm')} triggering immediately when metrics exceed fixed values (Check #{alarms_check.id}). This may result in false positives during normal operational variations."
                else:
                    check.current_level = 1
                    check.explanation = "No adaptive threshold mechanisms detected. Reliance on manual threshold setting without automated baseline determination or anomaly detection."
