# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Assessment scoring for metrics."""

from observability_assessment.text import plural


class MetricsScoringMixin:
    """Scoring methods that operate on ``self.results``."""

    def assess_metrics_maturity(self):
        """Assess metrics maturity based on discovery checks"""
        metrics_checks = [
            c for c in self.results.assessment_checks if c.category == "Metrics"
        ]

        for check in metrics_checks:
            if check.question_id == 5:  # What type of metrics do you collect?
                # Discovery checks for metrics collection
                custom_metrics_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Are you publishing custom business and application metrics to CloudWatch?"
                    ),
                    None,
                )
                ec2_detailed_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?"
                    ),
                    None,
                )
                ecs_monitoring_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "How many ECS clusters are available to monitor?"
                    ),
                    None,
                )
                ecs_insights_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have ECS clusters with Container Insights enabled?"
                    ),
                    None,
                )
                eks_addon_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have EKS clusters with the CloudWatch Observability add-on enabled?"
                    ),
                    None,
                )
                lambda_insights_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?"
                    ),
                    None,
                )
                cwagent_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Is the CloudWatch agent configured to collect system-level metrics?"
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
                    for c in [
                        custom_metrics_check,
                        ec2_detailed_check,
                        ecs_monitoring_check,
                        ecs_insights_check,
                        eks_addon_check,
                        lambda_insights_check,
                        cwagent_check,
                        app_signals_check,
                    ]
                    if c
                ]

                # Determine which compute types are in use
                active_compute = (
                    set(self.largest_log_groups.keys())
                    if self.largest_log_groups
                    else set()
                )

                # Check infrastructure metrics (enhanced monitoring per compute type)
                infra_signals = []
                if "EC2" in active_compute:
                    # The JMESPath query yields one (possibly empty) list per
                    # reservation, so count instances, not reservations.
                    ec2_detailed_instances = (
                        [
                            instance
                            for item in ec2_detailed_check.result
                            for instance in (item if isinstance(item, list) else [item])
                        ]
                        if ec2_detailed_check
                        and isinstance(ec2_detailed_check.result, list)
                        else []
                    )
                    if ec2_detailed_instances:
                        infra_signals.append("EC2 detailed monitoring")
                    if (
                        cwagent_check
                        and cwagent_check.result
                        and isinstance(cwagent_check.result, dict)
                        and cwagent_check.result.get("Metrics")
                    ):
                        infra_signals.append("CloudWatch agent metrics")
                if "ECS" in active_compute:
                    if (
                        ecs_insights_check
                        and ecs_insights_check.result
                        and isinstance(ecs_insights_check.result, dict)
                    ):
                        clusters = ecs_insights_check.result.get("clusters", [])
                        # "enhanced" is Container Insights with enhanced
                        # observability, the value new clusters inherit when
                        # the account default is set to enhanced.
                        if any(
                            s.get("value") in ("enabled", "enhanced")
                            for c in clusters
                            for s in c.get("settings", [])
                            if s.get("name") == "containerInsights"
                        ):
                            infra_signals.append("ECS Container Insights")
                if (
                    "EKS" in active_compute
                    and eks_addon_check
                    and eks_addon_check.result
                    and isinstance(eks_addon_check.result, dict)
                    and eks_addon_check.result.get("observability_clusters", 0) > 0
                ):
                    infra_signals.append("EKS CloudWatch Observability add-on")
                if (
                    "Lambda" in active_compute
                    and lambda_insights_check
                    and isinstance(lambda_insights_check.result, dict)
                    and lambda_insights_check.result.get("insights_functions", 0) > 0
                ):
                    infra_signals.append("Lambda Insights")

                has_custom = (
                    custom_metrics_check
                    and isinstance(custom_metrics_check.result, dict)
                    and custom_metrics_check.result.get("total_custom_metrics", 0) > 0
                )
                has_app_signals = (
                    app_signals_check
                    and isinstance(app_signals_check.result, dict)
                    and app_signals_check.result.get("Services")
                )

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = list(infra_signals)
                if has_custom:
                    capabilities.append(
                        f"{plural(custom_metrics_check.result.get('total_custom_metrics', 0), 'custom metric')} in {', '.join(custom_metrics_check.result.get('custom_namespaces', []))}"
                    )
                if has_app_signals:
                    capabilities.append(
                        f"Application Signals ({plural(len(app_signals_check.result['Services']), 'service')})"
                    )

                # L4: Infrastructure + application + custom + dimensions/app signals
                if has_custom and has_app_signals and infra_signals:
                    check.current_level = 4
                    check.explanation = f"Comprehensive metrics with {', '.join(capabilities)}. Infrastructure, application, and custom metrics with Application Signals providing dimensional metadata for diagnosing issues {evidence_refs}."
                # L3: Infrastructure + application + custom metrics
                elif has_custom and infra_signals:
                    check.current_level = 3
                    check.explanation = f"Infrastructure, application, and custom metrics with {', '.join(capabilities)} {evidence_refs}."
                # L2: Infrastructure + application metrics (enhanced monitoring)
                elif infra_signals:
                    check.current_level = 2
                    check.explanation = f"Infrastructure and application metrics via {', '.join(capabilities)} {evidence_refs}."
                # L1: Basic infrastructure metrics only
                else:
                    check.current_level = 1
                    check.explanation = f"Basic infrastructure metrics only. No enhanced monitoring, custom metrics, or application-level metrics detected {evidence_refs}."

            elif check.question_id == 6:  # How do you use metrics?
                # Discovery checks for metrics usage
                dashboards_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch dashboards for visualizing metrics and logs?"
                        and "Metrics" in c.category
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
                anomaly_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use anomaly detection models for adaptive alarming?"
                    ),
                    None,
                )
                devops_agent_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [
                        dashboards_check,
                        alarms_check,
                        anomaly_check,
                        devops_agent_check,
                    ]
                    if c
                ]

                has_dashboards = (
                    dashboards_check
                    and isinstance(dashboards_check.result, dict)
                    and dashboards_check.result.get("DashboardEntries")
                )
                has_alarms = (
                    alarms_check
                    and isinstance(alarms_check.result, dict)
                    and (
                        alarms_check.result.get("MetricAlarms")
                        or alarms_check.result.get("CompositeAlarms")
                    )
                )
                has_anomaly = (
                    anomaly_check
                    and isinstance(anomaly_check.result, dict)
                    and anomaly_check.result.get("total_bands", 0) > 0
                )
                has_devops_agent = (
                    devops_agent_check
                    and isinstance(devops_agent_check.result, dict)
                    and devops_agent_check.result.get("total_spaces", 0) > 0
                )

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_dashboards:
                    capabilities.append(
                        f"{plural(len(dashboards_check.result['DashboardEntries']), 'dashboard')}"
                    )
                if has_alarms:
                    alarm_count = len(
                        alarms_check.result.get("MetricAlarms", [])
                    ) + len(alarms_check.result.get("CompositeAlarms", []))
                    capabilities.append(f"{plural(alarm_count, 'alarm')}")
                if has_anomaly:
                    capabilities.append(
                        f"{plural(anomaly_check.result.get('total_bands', 0), 'anomaly detector')}"
                    )
                if has_devops_agent:
                    capabilities.append("AWS DevOps Agent")

                # L4: AI/ML capabilities (anomaly detection + AWS DevOps Agent)
                if has_anomaly and has_devops_agent:
                    check.current_level = 4
                    check.explanation = f"AI/ML-driven metrics usage with {', '.join(capabilities)}. Proactive issue identification via anomaly detection and AI-assisted troubleshooting {evidence_refs}."
                # L3: Automation and anomaly detection
                elif has_anomaly and has_alarms:
                    check.current_level = 3
                    check.explanation = f"Automated metrics usage with {', '.join(capabilities)}. Anomaly detection drives corrective action with high signal-to-noise ratio {evidence_refs}."
                # L2: Dashboards + alarms for operational visibility
                elif has_dashboards and has_alarms:
                    check.current_level = 2
                    check.explanation = f"Operational visibility with {', '.join(capabilities)}. Dashboards and alarms enable manual reaction to issues {evidence_refs}."
                # L1: Manual exploration
                else:
                    check.current_level = 1
                    check.explanation = f"Manual metrics exploration. {'Found ' + ', '.join(capabilities) + ' but' if capabilities else 'No dashboards or alarms detected —'} limited systematic usage {evidence_refs}."

            elif check.question_id == 7:  # How do you access metrics?
                # Discovery checks for metrics access
                streams_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you configured metric streams for real-time export to third-party tools or data lakes?"
                    ),
                    None,
                )
                oam_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Are you using CloudWatch cross-account observability?"
                    ),
                    None,
                )
                dashboards_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch dashboards for visualizing metrics and logs?"
                        and "Metrics" in c.category
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
                devops_agent_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"
                    ),
                    None,
                )

                omni_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use CloudWatch Omni spaces for unified access to logs, metrics, and traces?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [
                        streams_check,
                        oam_check,
                        dashboards_check,
                        anomaly_check,
                        devops_agent_check,
                        omni_check,
                    ]
                    if c
                ]

                has_streams = (
                    streams_check
                    and isinstance(streams_check.result, dict)
                    and streams_check.result.get("Entries")
                )
                has_oam = (
                    oam_check
                    and isinstance(oam_check.result, dict)
                    and (
                        oam_check.result.get("links_count", 0) > 0
                        or oam_check.result.get("sinks_count", 0) > 0
                    )
                )
                has_dashboards = (
                    dashboards_check
                    and isinstance(dashboards_check.result, dict)
                    and dashboards_check.result.get("DashboardEntries")
                )
                has_anomaly = (
                    anomaly_check
                    and isinstance(anomaly_check.result, dict)
                    and anomaly_check.result.get("total_bands", 0) > 0
                )
                has_devops_agent = (
                    devops_agent_check
                    and isinstance(devops_agent_check.result, dict)
                    and devops_agent_check.result.get("total_spaces", 0) > 0
                )
                has_omni = (
                    omni_check
                    and isinstance(omni_check.result, dict)
                    and omni_check.result.get("active_spaces", 0) > 0
                )
                has_enterprise_access = has_streams or has_oam or has_omni

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_dashboards:
                    capabilities.append(
                        f"{plural(len(dashboards_check.result['DashboardEntries']), 'dashboard')}"
                    )
                if has_streams:
                    capabilities.append(
                        f"{plural(len(streams_check.result['Entries']), 'metric stream')}"
                    )
                if has_oam:
                    capabilities.append("cross-account observability (OAM)")
                if has_anomaly:
                    capabilities.append("anomaly detection")
                if has_devops_agent:
                    capabilities.append("AWS DevOps Agent")
                if has_omni:
                    capabilities.append("CloudWatch Omni unified access")

                # L4: Automated insights with proactive root cause
                if has_enterprise_access and has_anomaly and has_devops_agent:
                    check.current_level = 4
                    check.explanation = f"Centralized metrics with automated insights via {', '.join(capabilities)}. Proactive root cause identification with AI-assisted resolution {evidence_refs}."
                # L3: Correlation and anomaly detection
                elif has_enterprise_access and has_anomaly:
                    check.current_level = 3
                    check.explanation = f"Centralized metrics with correlation via {', '.join(capabilities)}. Anomaly detection enables immediate root cause determination {evidence_refs}."
                # L2: Enterprise-wide visibility
                elif has_dashboards and has_enterprise_access:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide metrics visibility with {', '.join(capabilities)}. Teams can analyze and troubleshoot across data sources {evidence_refs}."
                # L1: Basic centralized collection
                elif has_dashboards:
                    check.current_level = 1
                    check.explanation = f"Basic centralized metrics access with {', '.join(capabilities)}. Lacks cross-account streaming or unified enterprise access {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"Basic metrics access without centralized management or unified visibility {evidence_refs}."
