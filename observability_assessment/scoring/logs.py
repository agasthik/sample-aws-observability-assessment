# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Assessment scoring for logs."""

from observability_assessment.text import plural


class LogsScoringMixin:
    """Scoring methods that operate on ``self.results``."""

    def assess_logs_maturity(self):
        """Assess logs maturity based on discovery checks"""
        log_checks = [c for c in self.results.assessment_checks if c.category == "Logs"]

        for check in log_checks:
            if check.question_id == 1:  # How do you collect logs?
                # Discovery checks for log collection
                log_groups_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)?"
                    ),
                    None,
                )
                ec2_agent_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of EC2 instances have the CloudWatch agent installed with both system metrics AND application logs configured?"
                    ),
                    None,
                )
                lambda_logs_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of Lambda functions use JSON structured logging?"
                    ),
                    None,
                )
                ecs_logs_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of ECS tasks use structured logging (JSON)?"
                    ),
                    None,
                )
                eks_logs_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?"
                    ),
                    None,
                )
                eks_addon_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?"
                        and c.category == "Logs"
                    ),
                    None,
                )
                structured_json_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of application logs use structured JSON format for easier parsing and analysis?"
                    ),
                    None,
                )
                centralization_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you implemented cross-account and cross-Region log centralization?"
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
                anomaly_detection_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "Have you enabled anomaly detection?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [
                        log_groups_check,
                        ec2_agent_check,
                        lambda_logs_check,
                        ecs_logs_check,
                        eks_logs_check,
                        eks_addon_check,
                        structured_json_check,
                        centralization_check,
                        oam_check,
                        anomaly_detection_check,
                    ]
                    if c
                ]

                # Determine which compute types are in use based on largest log groups
                compute_in_use = {
                    k: v for k, v in (self.largest_log_groups or {}).items() if v
                }
                compute_with_logging = {}

                def _found(discovery_check, key):
                    # Credit a compute type only when its check succeeded AND
                    # found logging configured; a successful 0% is not coverage.
                    return (
                        discovery_check
                        and discovery_check.status == "success"
                        and isinstance(discovery_check.result, dict)
                        and discovery_check.result.get(key, 0) > 0
                    )

                if "EC2" in compute_in_use and _found(
                    ec2_agent_check, "logging_configured_count"
                ):
                    compute_with_logging["EC2"] = "CloudWatch agent configured"
                if "Lambda" in compute_in_use and _found(
                    lambda_logs_check, "json_logging_count"
                ):
                    compute_with_logging["Lambda"] = "JSON structured logging"
                if "ECS" in compute_in_use and _found(
                    ecs_logs_check, "logging_configured_count"
                ):
                    compute_with_logging["ECS"] = "task logging configured"
                if "EKS" in compute_in_use and _found(eks_logs_check, "enabled_types"):
                    compute_with_logging["EKS"] = "control plane logs enabled"

                # Coverage ratio of compute types that have logging vs compute types in use
                coverage = (
                    len(compute_with_logging) / len(compute_in_use)
                    if compute_in_use
                    else 0
                )

                # Check higher-level signals
                has_structured_json = (
                    structured_json_check
                    and isinstance(structured_json_check.result, dict)
                    and structured_json_check.result.get("json_groups", 0) > 0
                ) or (
                    lambda_logs_check
                    and isinstance(lambda_logs_check.result, dict)
                    and lambda_logs_check.result.get("json_logging_count", 0) > 0
                )
                has_centralization = (
                    centralization_check
                    and isinstance(centralization_check.result, dict)
                    and centralization_check.result.get("centralization_patterns")
                ) or (
                    oam_check
                    and isinstance(oam_check.result, dict)
                    and (
                        oam_check.result.get("links_count", 0) > 0
                        or oam_check.result.get("sinks_count", 0) > 0
                    )
                )
                has_eks_addon = (
                    eks_addon_check
                    and isinstance(eks_addon_check.result, dict)
                    and eks_addon_check.result.get("observability_clusters", 0) > 0
                )
                has_anomaly_detection = (
                    anomaly_detection_check
                    and isinstance(anomaly_detection_check.result, dict)
                    and len(anomaly_detection_check.result.get("anomalyDetectors", []))
                    > 0
                )
                has_log_groups = (
                    log_groups_check
                    and isinstance(log_groups_check.result, dict)
                    and log_groups_check.result.get("total_log_groups", 0) > 0
                )

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                compute_summary = ", ".join(
                    f"{k}: {v}" for k, v in compute_with_logging.items()
                )
                in_use_summary = ", ".join(compute_in_use.keys())

                # L4: Automated collection with ML-based analysis
                if (
                    coverage >= 0.75
                    and has_structured_json
                    and has_centralization
                    and (has_eks_addon or has_anomaly_detection)
                ):
                    check.current_level = 4
                    extras = []
                    if has_eks_addon:
                        extras.append(
                            "EKS Observability add-on for auto-instrumented collection"
                        )
                    if has_anomaly_detection:
                        extras.append("log anomaly detection")
                    check.explanation = f"Automated log collection with ML-based analysis. Compute coverage: {compute_summary}. Additional: {', '.join(extras)}. Structured JSON logging and centralization in place {evidence_refs}."
                # L3: Correlation patterns via centralization + structured logs
                elif coverage >= 0.75 and has_structured_json and has_centralization:
                    check.current_level = 3
                    check.explanation = f"Centralized log collection with correlation patterns. Compute coverage: {compute_summary}. Structured JSON logging enables correlation across services. Cross-account/Region centralization provides a unified view {evidence_refs}."
                # L2: Good coverage of in-use compute types with structured logging
                elif coverage >= 0.5 and (
                    has_structured_json or len(compute_with_logging) >= 2
                ):
                    check.current_level = 2
                    check.explanation = f"Centralized collection with analytics across compute types in use ({in_use_summary}). Logging configured for: {compute_summary} {evidence_refs}."
                # L1: Some logging exists
                elif has_log_groups or compute_with_logging:
                    check.current_level = 1
                    if compute_with_logging:
                        check.explanation = f"Basic log collection. Compute types in use: {in_use_summary}. Logging configured for: {compute_summary}. Coverage gap needs attention {evidence_refs}."
                    else:
                        check.explanation = f"Basic log groups exist, but compute-specific log collection is not fully configured for the compute types in use ({in_use_summary}) {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = (
                        f"Minimal log collection detected {evidence_refs}."
                    )

            elif check.question_id == 2:  # How do you use logs?
                # Discovery checks for log usage
                query_definitions_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have standardized Logs Insights queries for common troubleshooting scenarios (errors, latency, security events)?"
                    ),
                    None,
                )
                metric_filters_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you created metric filters to extract KPIs from logs?"
                    ),
                    None,
                )
                anomaly_detection_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "Have you enabled anomaly detection?"
                    ),
                    None,
                )
                structured_json_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of application logs use structured JSON format for easier parsing and analysis?"
                    ),
                    None,
                )
                field_indexes_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have field index policies configured for faster log queries?"
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
                lambda_json_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of Lambda functions use JSON structured logging?"
                    ),
                    None,
                )
                ecs_json_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of ECS tasks use structured logging (JSON)?"
                    ),
                    None,
                )
                stale_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have stale or unused log groups that are collecting data but not being used?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [
                        query_definitions_check,
                        metric_filters_check,
                        anomaly_detection_check,
                        structured_json_check,
                        field_indexes_check,
                        devops_agent_check,
                        lambda_json_check,
                        ecs_json_check,
                        stale_check,
                    ]
                    if c
                ]

                has_saved_queries = (
                    query_definitions_check
                    and query_definitions_check.result
                    and query_definitions_check.result.get("queryDefinitions")
                )
                has_metric_filters = (
                    metric_filters_check
                    and metric_filters_check.result
                    and metric_filters_check.result.get("metricFilters")
                )
                has_anomaly_detection = (
                    anomaly_detection_check
                    and isinstance(anomaly_detection_check.result, dict)
                    and len(anomaly_detection_check.result.get("anomalyDetectors", []))
                    > 0
                )
                has_structured_json = (
                    structured_json_check
                    and isinstance(structured_json_check.result, dict)
                    and structured_json_check.result.get("json_groups", 0) > 0
                ) or (
                    lambda_json_check
                    and isinstance(lambda_json_check.result, dict)
                    and lambda_json_check.result.get("json_logging_count", 0) > 0
                )
                has_field_indexes = (
                    field_indexes_check
                    and isinstance(field_indexes_check.result, dict)
                    and field_indexes_check.result.get("indexed_log_groups", 0) > 0
                )
                has_devops_agent = (
                    devops_agent_check
                    and isinstance(devops_agent_check.result, dict)
                    and devops_agent_check.result.get("total_spaces", 0) > 0
                )

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_saved_queries:
                    q_count = len(query_definitions_check.result["queryDefinitions"])
                    capabilities.append(
                        f"{plural(q_count, 'saved Logs Insights query', 'saved Logs Insights queries')}"
                    )
                if has_metric_filters:
                    mf_count = len(metric_filters_check.result["metricFilters"])
                    capabilities.append(f"{plural(mf_count, 'metric filter')}")
                if has_anomaly_detection:
                    capabilities.append("log anomaly detection")
                if has_structured_json:
                    capabilities.append("structured JSON logging")
                if has_field_indexes:
                    capabilities.append("field index policies")
                if has_devops_agent:
                    capabilities.append(
                        "AWS DevOps Agent for AI-assisted troubleshooting"
                    )

                # Stale log groups signal
                stale_pct = 0
                stale_warning = ""
                if (
                    stale_check
                    and isinstance(stale_check.result, dict)
                    and stale_check.result.get("total_checked", 0) > 0
                ):
                    stale_pct = stale_check.result.get("stale_percentage", 0)
                    stale_count = stale_check.result.get("stale_log_groups", 0)
                    if stale_pct > 0:
                        stale_warning = f" Warning: {stale_count} of {plural(stale_check.result['total_checked'], 'largest log group')} {'is' if stale_count == 1 else 'are'} stale ({stale_pct}%) — logs collected but not actively used."

                # L4: Automated resolution — anomaly detection + metric filters (logs→metrics→alarms) + AI resolution
                if has_anomaly_detection and has_metric_filters and has_devops_agent:
                    check.current_level = 4
                    check.explanation = f"Automated resolution and MTTR reduction with {', '.join(capabilities)}. Logs drive automated alerting via metric filters, anomaly detection identifies issues proactively, and AWS DevOps Agent enables AI-assisted resolution {evidence_refs}.{stale_warning}"
                # L3: Automated correlation and anomaly detection
                elif has_anomaly_detection and (
                    has_metric_filters or has_saved_queries
                ):
                    check.current_level = 3
                    check.explanation = f"Automated correlation and anomaly detection with {', '.join(capabilities)}. Anomaly detection proactively identifies issues while structured analysis capabilities enable faster root cause identification {evidence_refs}.{stale_warning}"
                # L2: Structured queries with faster analysis
                elif (
                    has_saved_queries
                    or has_metric_filters
                    or (has_structured_json and has_field_indexes)
                ):
                    check.current_level = 2
                    check.explanation = f"Structured queries with faster analysis using {', '.join(capabilities)}. Repeatable analysis patterns and log-derived metrics enable faster troubleshooting beyond manual searches {evidence_refs}.{stale_warning}"
                # L1: Manual log searches
                else:
                    check.current_level = 1
                    if capabilities:
                        check.explanation = f"Basic log usage with {', '.join(capabilities)}. Limited structured analysis — primarily manual log searches for troubleshooting {evidence_refs}.{stale_warning}"
                    else:
                        check.explanation = f"Log usage limited to manual searches and basic queries. No saved queries, metric filters, or anomaly detection detected {evidence_refs}.{stale_warning}"

            elif check.question_id == 3:  # How do you access logs?
                # Discovery checks for log access
                log_groups_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)?"
                    ),
                    None,
                )
                dashboards_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch dashboards for visualizing metrics and logs?"
                        and "Logs" in c.category
                    ),
                    None,
                )
                subscription_filters_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of the largest log groups have subscription filters for real-time processing?"
                    ),
                    None,
                )
                centralization_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you implemented cross-account and cross-Region log centralization?"
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
                anomaly_detection_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "Have you enabled anomaly detection?"
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
                investigations_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you configured CloudWatch Investigations actions for any alarms?"
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
                        log_groups_check,
                        dashboards_check,
                        subscription_filters_check,
                        centralization_check,
                        oam_check,
                        anomaly_detection_check,
                        devops_agent_check,
                        investigations_check,
                        omni_check,
                    ]
                    if c
                ]

                has_log_groups = (
                    log_groups_check
                    and isinstance(log_groups_check.result, dict)
                    and log_groups_check.result.get("total_log_groups", 0) > 0
                )
                has_dashboards = (
                    dashboards_check
                    and dashboards_check.result
                    and dashboards_check.result.get("DashboardEntries")
                )
                has_subscription_filters = (
                    subscription_filters_check
                    and subscription_filters_check.result
                    and subscription_filters_check.result.get(
                        "groups_with_subscription_filters", 0
                    )
                    > 0
                )
                has_centralization = (
                    centralization_check
                    and isinstance(centralization_check.result, dict)
                    and centralization_check.result.get("centralization_patterns")
                )
                has_oam = (
                    oam_check
                    and isinstance(oam_check.result, dict)
                    and (
                        oam_check.result.get("links_count", 0) > 0
                        or oam_check.result.get("sinks_count", 0) > 0
                    )
                )
                has_anomaly_detection = (
                    anomaly_detection_check
                    and isinstance(anomaly_detection_check.result, dict)
                    and len(anomaly_detection_check.result.get("anomalyDetectors", []))
                    > 0
                )
                has_devops_agent = (
                    devops_agent_check
                    and isinstance(devops_agent_check.result, dict)
                    and devops_agent_check.result.get("total_spaces", 0) > 0
                )
                has_investigations = (
                    investigations_check
                    and isinstance(investigations_check.result, dict)
                    and investigations_check.result.get("alarms_with_investigations", 0)
                    > 0
                )
                has_omni = (
                    omni_check
                    and isinstance(omni_check.result, dict)
                    and omni_check.result.get("active_spaces", 0) > 0
                )
                has_enterprise_access = (
                    has_centralization
                    or has_oam
                    or has_subscription_filters
                    or has_omni
                )

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_dashboards:
                    capabilities.append(
                        f"{plural(len(dashboards_check.result['DashboardEntries']), 'dashboard')}"
                    )
                if has_centralization:
                    capabilities.append("cross-account/region log centralization")
                if has_oam:
                    capabilities.append("CloudWatch cross-account observability (OAM)")
                if has_subscription_filters:
                    sf_count = subscription_filters_check.result.get(
                        "groups_with_subscription_filters", 0
                    )
                    capabilities.append(
                        f"{plural(sf_count, 'log group')} with subscription filters"
                    )
                if has_anomaly_detection:
                    capabilities.append("log anomaly detection")
                if has_devops_agent:
                    capabilities.append("AWS DevOps Agent")
                if has_investigations:
                    capabilities.append("CloudWatch Investigations")
                if has_omni:
                    capabilities.append("CloudWatch Omni unified access")

                # L4: Automated insights with proactive root cause
                if (
                    has_enterprise_access
                    and has_anomaly_detection
                    and (has_devops_agent or has_investigations)
                ):
                    check.current_level = 4
                    check.explanation = f"Automated insights with proactive root cause identification via {', '.join(capabilities)}. Enterprise-wide log access with anomaly detection and AI-assisted root cause analysis {evidence_refs}."
                # L3: Single pane correlation and anomaly detection
                elif has_enterprise_access and has_anomaly_detection:
                    check.current_level = 3
                    check.explanation = f"Single pane correlation and anomaly detection with {', '.join(capabilities)}. Centralized access combined with anomaly detection enables immediate root cause determination {evidence_refs}."
                # L2: Enterprise-wide visibility
                elif has_dashboards and has_enterprise_access:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide visibility with {', '.join(capabilities)}. Relevant teams can analyze and troubleshoot based on captured information with centralized access patterns {evidence_refs}."
                # L1: Basic centralized collection
                elif has_log_groups:
                    check.current_level = 1
                    if capabilities:
                        check.explanation = f"Basic centralized log access with {', '.join(capabilities)}. Foundation for enterprise visibility but lacks unified cross-account access or correlation capabilities {evidence_refs}."
                    else:
                        check.explanation = f"Basic centralized collection — log groups exist but no dashboards, centralization, or cross-account access detected {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"Minimal log access detected. No centralized collection or access mechanisms found {evidence_refs}."

            elif check.question_id == 4:  # What is your log retention policy?
                # Discovery checks for log retention
                top_groups_retention_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of the largest log groups have retention policies configured (example thresholds: security: 90+ days, operational: 30 days, debug: 7 days — actual requirements vary by organization)?"
                    ),
                    None,
                )
                export_tasks_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have log export tasks configured for archival?"
                    ),
                    None,
                )
                subscription_filters_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of the largest log groups have subscription filters for real-time processing?"
                    ),
                    None,
                )
                centralization_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you implemented cross-account and cross-Region log centralization?"
                    ),
                    None,
                )
                tags_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do your log groups have resource tags for retention governance and metadata-based search?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [
                        top_groups_retention_check,
                        export_tasks_check,
                        subscription_filters_check,
                        centralization_check,
                        tags_check,
                    ]
                    if c
                ]

                # Analyze retention coverage from top 10 largest log groups
                retention_ratio = 0.0
                total_groups_checked = 0
                groups_with_retention = 0
                if top_groups_retention_check and top_groups_retention_check.result:
                    groups_with_retention = top_groups_retention_check.result.get(
                        "groups_with_retention", 0
                    )
                    total_groups_checked = len(
                        top_groups_retention_check.result.get("top_log_groups", [])
                    )
                    if total_groups_checked > 0:
                        retention_ratio = groups_with_retention / total_groups_checked

                has_export_tasks = (
                    export_tasks_check
                    and isinstance(export_tasks_check.result, dict)
                    and export_tasks_check.result.get("exported_log_groups", 0) > 0
                )
                has_subscription_archival = (
                    subscription_filters_check
                    and isinstance(subscription_filters_check.result, dict)
                    and subscription_filters_check.result.get(
                        "groups_with_subscription_filters", 0
                    )
                    > 0
                )
                has_centralization = (
                    centralization_check
                    and isinstance(centralization_check.result, dict)
                    and centralization_check.result.get("centralization_patterns")
                )
                has_archival = (
                    has_export_tasks or has_subscription_archival or has_centralization
                )
                has_log_group_tags = (
                    tags_check
                    and isinstance(tags_check.result, dict)
                    and tags_check.result.get("total_tagged_log_groups", 0) > 0
                )

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if total_groups_checked > 0:
                    capabilities.append(
                        f"retention policies on {groups_with_retention}/{total_groups_checked} largest log groups ({retention_ratio:.0%} coverage)"
                    )
                if has_export_tasks:
                    capabilities.append(
                        f"export tasks on {plural(export_tasks_check.result.get('exported_log_groups', 0), 'log group')}"
                    )
                if has_subscription_archival:
                    capabilities.append(
                        f"subscription filters on {plural(subscription_filters_check.result.get('groups_with_subscription_filters', 0), 'log group')} for streaming/archival"
                    )
                if has_centralization:
                    capabilities.append("cross-account/region log centralization")
                if has_log_group_tags:
                    capabilities.append(
                        f"log group tagging ({plural(tags_check.result.get('total_tagged_log_groups', 0), 'tagged log group')})"
                    )

                # L4: Easy retrieval with metadata-based search (high retention coverage + archival + tagging)
                if retention_ratio >= 0.75 and has_archival and has_log_group_tags:
                    check.current_level = 4
                    check.explanation = f"Comprehensive retention strategy with {', '.join(capabilities)}. High retention coverage combined with archival pipelines and resource tagging enables metadata-based search and easy retrieval {evidence_refs}."
                # L3: Automated archival with cost optimization (good retention + archival)
                elif retention_ratio >= 0.50 and has_archival:
                    check.current_level = 3
                    check.explanation = f"Automated archival with cost optimization via {', '.join(capabilities)}. Retention policies combined with archival mechanisms (export/subscription/centralization) provide tiered storage for cost optimization {evidence_refs}."
                # L2: Enterprise-wide compliance-based policies (retention policies on majority of groups)
                elif retention_ratio >= 0.50:
                    check.current_level = 2
                    check.explanation = f"Enterprise-wide retention policies with {', '.join(capabilities)}. Consistent retention settings across major log groups indicate compliance-based lifecycle management {evidence_refs}."
                # L1: Disparate retention policies
                elif groups_with_retention > 0:
                    check.current_level = 1
                    check.explanation = f"Partial retention coverage with {', '.join(capabilities)}. Some log groups have retention policies but coverage is below 50%, indicating disparate department-level policies {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"No retention policies detected on largest log groups. Logs may be using the default retention setting ('Never expire'), leading to uncontrolled storage costs {evidence_refs}."
