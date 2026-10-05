# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Assessment scoring for organization."""

from observability_assessment.text import plural


class OrganizationScoringMixin:
    """Scoring methods that operate on ``self.results``."""

    def assess_organization_maturity(self):
        """Assess organization maturity based on discovery checks"""
        org_checks = [
            c for c in self.results.assessment_checks if c.category == "Organization"
        ]

        for check in org_checks:
            if check.question_id == 13:  # How do you use SLOs?
                app_signals_slo_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you defined Service Level Objectives (SLOs) for critical application services?"
                        and "Organization" in c.category
                    ),
                    None,
                )
                app_signals_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use CloudWatch Application Signals to monitor application services?"
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

                check.evidence_check_ids = [
                    c.id
                    for c in [app_signals_slo_check, app_signals_check, alarms_check]
                    if c
                ]

                has_slos = (
                    app_signals_slo_check
                    and app_signals_slo_check.result
                    and app_signals_slo_check.result.get("SloSummaries")
                )
                slo_count = (
                    len(app_signals_slo_check.result.get("SloSummaries", []))
                    if has_slos
                    else 0
                )
                has_app_signals = (
                    app_signals_check
                    and isinstance(app_signals_check.result, dict)
                    and app_signals_check.result.get("Services")
                )
                has_alarms = (
                    alarms_check
                    and alarms_check.result
                    and (
                        alarms_check.result.get("MetricAlarms")
                        or alarms_check.result.get("CompositeAlarms")
                    )
                )

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"

                # L4: Integrated platforms with error budgets — SLOs + App Signals + alarms working together
                if has_slos and has_app_signals and has_alarms:
                    check.current_level = 4
                    check.explanation = f"Integrated SLO platform with {plural(slo_count, 'SLO')} configured through Application Signals, backed by alarms for error budget tracking {evidence_refs}. This indicates integrated platforms with error budgets and business-aligned reliability targets."
                # L3: Prioritization for users and business — SLOs defined and actively used
                elif has_slos and has_app_signals:
                    check.current_level = 3
                    check.explanation = f"Found {plural(slo_count, 'SLO')} configured through Application Signals {evidence_refs}. SLOs are defined with service-level visibility but lack alarm integration for error budget enforcement."
                # L2: Enterprise adoption for reliability — App Signals adopted but no SLOs yet
                elif has_slos or has_app_signals:
                    check.current_level = 2
                    details = (
                        f"{plural(slo_count, 'SLO')} defined"
                        if has_slos
                        else "Application Signals enabled for service monitoring"
                    )
                    check.explanation = f"Early SLO adoption detected: {details} {evidence_refs}. Enterprise adoption is underway but not yet fully integrated with error budgets and business prioritization."
                # L1: Team experimentation without adoption
                else:
                    check.current_level = 1
                    check.explanation = f"No formal SLO implementation detected {evidence_refs}. The account may have team-level experimentation but lacks enterprise adoption for systematic reliability management."

            elif (
                check.question_id == 17
            ):  # Are you getting ROI from your observability tools?
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
                alarms_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch alarms configured for your resources?"
                    ),
                    None,
                )
                retention_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of the largest log groups have retention policies configured (example thresholds: security: 90+ days, operational: 30 days, debug: 7 days — actual requirements vary by organization)?"
                    ),
                    None,
                )
                tags_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use resource tags for organizing and managing AWS resources?"
                    ),
                    None,
                )
                export_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have log export tasks configured for archival?"
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
                stale_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have stale or unused log groups that are collecting data but not being used?"
                    ),
                    None,
                )
                slo_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you defined Service Level Objectives (SLOs) for critical application services?"
                        and "Organization" in c.category
                    ),
                    None,
                )

                all_checks = [
                    dashboards_check,
                    alarms_check,
                    retention_check,
                    tags_check,
                    export_check,
                    composite_check,
                    stale_check,
                    slo_check,
                ]
                check.evidence_check_ids = [c.id for c in all_checks if c]
                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"

                # Tool consolidation: dashboards + alarms in a single platform
                has_dashboards = bool(
                    dashboards_check
                    and dashboards_check.result
                    and dashboards_check.result.get("DashboardEntries")
                )
                has_alarms = bool(
                    alarms_check
                    and alarms_check.result
                    and alarms_check.result.get("MetricAlarms")
                )
                has_consolidated = has_dashboards and has_alarms

                retention_result = (
                    retention_check.result
                    if retention_check and isinstance(retention_check.result, dict)
                    else {}
                )
                retention_count = retention_result.get("groups_with_retention", 0)
                retention_total = len(retention_result.get("top_log_groups", []))
                retention_ratio = (
                    retention_count / retention_total if retention_total else 0.0
                )
                has_retention_governance = retention_ratio >= 0.50
                has_high_retention = retention_ratio >= 0.80

                has_export = bool(
                    export_check
                    and isinstance(export_check.result, dict)
                    and export_check.result.get("exported_log_groups", 0) > 0
                )
                has_tags = bool(
                    tags_check
                    and tags_check.result
                    and tags_check.result.get("ResourceTagMappingList")
                )
                has_composite = bool(
                    composite_check
                    and composite_check.result
                    and composite_check.result.get("CompositeAlarms")
                )
                stale_result = (
                    stale_check.result
                    if stale_check and isinstance(stale_check.result, dict)
                    else {}
                )
                stale_total = stale_result.get("total_checked", 0)
                stale_percentage = stale_result.get("stale_percentage", 100)
                has_active_usage = stale_total > 0 and stale_percentage <= 10
                has_slos = bool(
                    slo_check
                    and isinstance(slo_check.result, dict)
                    and slo_check.result.get("SloSummaries")
                )

                cost_signals = [
                    s
                    for s in [
                        f"retention policies on {retention_count}/{retention_total} sampled log groups"
                        if has_retention_governance
                        else None,
                        "log archival" if has_export else None,
                        "resource tagging" if has_tags else None,
                        "composite alarms" if has_composite else None,
                        f"active log usage ({100 - stale_percentage:.0f}% of the sample)"
                        if has_active_usage
                        else None,
                    ]
                    if s
                ]

                manual_questions_l3 = "To assess Level 3, ask: (1) Do you track total observability spend across all tools? (2) Have you consolidated or eliminated redundant tooling? (3) Do you review which logs/metrics you collect vs. actually use? (4) Do you use tiered storage (Infrequent Access log class, S3 archival) for rarely accessed data?"
                manual_questions_l4 = "To assess Level 4, ask: (1) Can you tie observability investment to business outcomes (uptime SLAs, revenue protection)? (2) Do you measure MTTR improvement from observability investments? (3) Do you track observability cost per workload or team? (4) Does leadership view observability as a value driver rather than a cost center?"

                dashboard_count = (
                    len(dashboards_check.result.get("DashboardEntries", []))
                    if has_dashboards
                    else 0
                )
                alarm_count = (
                    len(alarms_check.result.get("MetricAlarms", []))
                    if has_alarms
                    else 0
                )

                # L4: Business value and cost optimization — consolidated tooling,
                # business-aligned SLOs, and broad cost-governance evidence.
                if (
                    has_consolidated
                    and has_slos
                    and has_high_retention
                    and len(cost_signals) >= 4
                ):
                    check.current_level = 4
                    check.explanation = f"Business-aligned cost optimization detected with {plural(dashboard_count, 'dashboard')} and {plural(alarm_count, 'alarm')} centralized in CloudWatch, formal SLOs, and cost governance through {', '.join(cost_signals)} {evidence_refs}. These configuration signals support Level 4; validate measured MTTR, availability, and business outcomes separately. {manual_questions_l4}"
                # L3: Established validation policies — consolidated tooling plus
                # multiple independently observable governance controls.
                elif has_consolidated and len(cost_signals) >= 2:
                    check.current_level = 3
                    check.explanation = f"Established observability governance detected with {plural(dashboard_count, 'dashboard')} and {plural(alarm_count, 'alarm')} centralized in CloudWatch plus {', '.join(cost_signals)} {evidence_refs}. These controls indicate active cost and usage validation. {manual_questions_l4}"
                # L2: Vendor consolidation — dashboards + alarms in CloudWatch.
                elif has_consolidated:
                    check.current_level = 2
                    check.explanation = f"Tool consolidation detected with {plural(dashboard_count, 'dashboard')} and {plural(alarm_count, 'alarm')} centralized in CloudWatch {evidence_refs}. {manual_questions_l3}"
                # L1: Want optimization without knowledge
                else:
                    check.current_level = 1
                    check.explanation = f"Limited evidence of observability tool consolidation {evidence_refs}. {manual_questions_l3}"

            elif check.question_id == 14:  # Do you use any AI/ML capability today?
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
                investigations_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you configured CloudWatch Investigations actions for any alarms?"
                    ),
                    None,
                )
                log_anomaly_check = next(
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
                        anomaly_check,
                        devops_agent_check,
                        investigations_check,
                        log_anomaly_check,
                    ]
                    if c
                ]

                has_metric_anomaly = (
                    anomaly_check
                    and isinstance(anomaly_check.result, dict)
                    and anomaly_check.result.get("total_bands", 0) > 0
                )
                has_log_anomaly = (
                    log_anomaly_check
                    and isinstance(log_anomaly_check.result, dict)
                    and len(log_anomaly_check.result.get("anomalyDetectors", [])) > 0
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
                has_anomaly = has_metric_anomaly or has_log_anomaly

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"
                capabilities = []
                if has_metric_anomaly:
                    capabilities.append(
                        f"{plural(anomaly_check.result.get('total_bands', 0), 'metric anomaly detector')}"
                    )
                if has_log_anomaly:
                    capabilities.append(
                        f"{plural(len(log_anomaly_check.result.get('anomalyDetectors', [])), 'log anomaly detector')}"
                    )
                if has_devops_agent:
                    capabilities.append("AWS DevOps Agent (NL query)")
                if has_investigations:
                    capabilities.append("CloudWatch Investigations")

                # L4: Comprehensive AI/ML with real-time
                if has_anomaly and has_devops_agent and has_investigations:
                    check.current_level = 4
                    check.explanation = f"Comprehensive AI/ML with {', '.join(capabilities)}. Real-time anomaly detection combined with AI-assisted troubleshooting and automated investigations {evidence_refs}."
                # L3: Automatic correlation and patterns
                elif has_anomaly and (has_devops_agent or has_investigations):
                    check.current_level = 3
                    check.explanation = f"Automatic correlation and patterns with {', '.join(capabilities)} {evidence_refs}."
                # L2: Natural language query or automated investigation capability
                elif has_devops_agent or has_investigations:
                    check.current_level = 2
                    check.explanation = f"AI-assisted troubleshooting via {', '.join(capabilities)}, but without anomaly detection for automatic correlation {evidence_refs}."
                # L2: Basic anomaly detection without AI-assisted investigation
                elif has_anomaly:
                    check.current_level = 2
                    check.explanation = f"Basic AI/ML with {', '.join(capabilities)} but no natural language or automated investigation capabilities {evidence_refs}."
                else:
                    check.current_level = 1
                    check.explanation = f"No AI/ML features detected in the observability stack {evidence_refs}."

            elif check.question_id == 15:  # Do you have real end-user monitoring?
                rum_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use CloudWatch RUM to monitor real user experiences?"
                    ),
                    None,
                )
                synthetics_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use CloudWatch Synthetics to monitor application endpoints?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id for c in [rum_check, synthetics_check] if c
                ]

                has_rum = (
                    rum_check
                    and rum_check.result
                    and rum_check.result.get("AppMonitorSummaries")
                )
                canaries = (
                    synthetics_check.result.get("Canaries", [])
                    if synthetics_check and synthetics_check.result
                    else []
                )
                has_synthetics = len(canaries) > 0
                tracing_canaries = [
                    c for c in canaries if c.get("RunConfig", {}).get("ActiveTracing")
                ]
                has_synthetics_with_tracing = len(tracing_canaries) > 0

                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"

                # L4: Real user monitoring with proactive anomalies
                if has_rum:
                    rum_count = len(rum_check.result.get("AppMonitorSummaries", []))
                    extras = (
                        f" It also has {plural(len(canaries), 'Synthetics canary', 'Synthetics canaries')}."
                        if has_synthetics
                        else ""
                    )
                    check.current_level = 4
                    check.explanation = f"Real user monitoring with {plural(rum_count, 'RUM application')} capturing actual user experience data {evidence_refs}.{extras}"
                # L3: Scripted interaction tests with correlation (synthetics + X-Ray tracing)
                elif has_synthetics_with_tracing:
                    check.current_level = 3
                    check.explanation = f"Synthetic monitoring with X-Ray correlation: {len(tracing_canaries)} of {len(canaries)} canaries have active tracing enabled for end-to-end visibility {evidence_refs}."
                # L2: Synthetic scripts on schedule
                elif has_synthetics:
                    check.current_level = 2
                    check.explanation = f"Synthetic monitoring with {plural(len(canaries), 'CloudWatch Synthetics canary', 'CloudWatch Synthetics canaries')} running on a schedule {evidence_refs}. Enable X-Ray active tracing on canaries for L3 correlation."
                # L1: Test users for validation
                else:
                    check.current_level = 1
                    check.explanation = f"No end-user monitoring detected {evidence_refs}. Reliance on test users or manual validation."

            elif (
                check.question_id == 16
            ):  # Do you have an enterprise observability strategy?
                tags_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use resource tags for organizing and managing AWS resources?"
                    ),
                    None,
                )
                cross_account_check = next(
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
                        and "Dashboards" in c.category
                    ),
                    None,
                )
                structured_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "What percentage of application logs use structured JSON format for easier parsing and analysis?"
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
                slo_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you defined Service Level Objectives (SLOs) for critical application services?"
                    ),
                    None,
                )

                omni_spaces_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use CloudWatch Omni spaces for unified access to logs, metrics, and traces?"
                    ),
                    None,
                )
                omni_integrations_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you connected CloudWatch Omni integrations (Context Graph resource discovery, Slack, external agents)?"
                    ),
                    None,
                )

                all_checks = [
                    tags_check,
                    cross_account_check,
                    dashboards_check,
                    structured_check,
                    app_signals_check,
                    slo_check,
                    omni_spaces_check,
                    omni_integrations_check,
                ]
                check.evidence_check_ids = [c.id for c in all_checks if c]
                evidence_refs = f"(Checks #{', #'.join(str(id) for id in check.evidence_check_ids)})"

                has_tags = bool(
                    tags_check
                    and tags_check.result
                    and tags_check.result.get("ResourceTagMappingList")
                )
                has_oam = bool(
                    cross_account_check
                    and cross_account_check.result
                    and (
                        cross_account_check.result.get("links_count", 0) > 0
                        or cross_account_check.result.get("sinks_count", 0) > 0
                    )
                )
                # An active Omni space in an organization domain gives
                # organization-wide observability, equivalent to OAM for this signal.
                has_omni_org = bool(
                    omni_spaces_check
                    and isinstance(omni_spaces_check.result, dict)
                    and omni_spaces_check.result.get("active_spaces", 0) > 0
                    and omni_spaces_check.result.get("has_organization_domain")
                )
                has_omni_integrations = bool(
                    omni_integrations_check
                    and isinstance(omni_integrations_check.result, dict)
                    and omni_integrations_check.result.get("active_integrations", 0) > 0
                )
                has_cross_account = has_oam or has_omni_org
                has_dashboards = bool(
                    dashboards_check
                    and dashboards_check.result
                    and dashboards_check.result.get("DashboardEntries")
                )
                structured_result = (
                    structured_check.result
                    if structured_check and isinstance(structured_check.result, dict)
                    else {}
                )
                structured_total = structured_result.get("total_groups_checked", 0)
                structured_count = structured_result.get("json_groups", 0)
                structured_ratio = (
                    structured_count / structured_total if structured_total else 0.0
                )
                has_structured = structured_ratio > 0.50
                has_app_signals = bool(
                    app_signals_check
                    and app_signals_check.result
                    and app_signals_check.result.get("Services")
                )
                has_slos = bool(
                    slo_check
                    and isinstance(slo_check.result, dict)
                    and slo_check.result.get("SloSummaries")
                )

                strategy_signals = [
                    s
                    for s in [
                        "resource tagging" if has_tags else None,
                        (
                            "cross-account observability"
                            if has_oam
                            else "CloudWatch Omni organization domain"
                        )
                        if has_cross_account
                        else None,
                        "centralized dashboards" if has_dashboards else None,
                        f"structured logging ({structured_ratio:.0%} sampled coverage)"
                        if has_structured
                        else None,
                        "Application Signals" if has_app_signals else None,
                        "service-level objectives" if has_slos else None,
                    ]
                    if s
                ]

                manual_questions_l3 = "To assess Level 3, ask: (1) Do you have documented observability standards and naming conventions? (2) Do teams receive training on observability best practices? (3) Are there runbooks or playbooks tied to your alerts? (4) Do you conduct regular operational reviews (e.g., weekly ops meetings, post-incident reviews)?"
                manual_questions_l4 = "To assess Level 4, ask: (1) Is observability embedded in your CI/CD pipeline (e.g., auto-instrumentation, deployment gates based on SLOs)? (2) Do you have a dedicated observability team or CoE driving continuous improvement? (3) Do teams proactively improve observability coverage without being asked? (4) Does leadership champion observability as a strategic capability?"

                # L4: Culture of continuous improvement — all observable strategy
                # proxies are present. Organizational culture still needs manual
                # validation because it cannot be proven from AWS configuration.
                if len(strategy_signals) == 6:
                    check.current_level = 4
                    check.explanation = f"Broad, integrated observability strategy detected across {', '.join(strategy_signals)} {evidence_refs}. The combination of standards, centralized visibility, application monitoring, and SLOs is consistent with a continuous-improvement operating model. Validate cultural adoption separately. {manual_questions_l4}"
                # L3: Established practices and training — require broad technical
                # adoption plus evidence of both standardization and enterprise scope.
                elif (
                    len(strategy_signals) >= 4
                    and (has_tags or has_structured)
                    and (has_cross_account or has_slos)
                ):
                    check.current_level = 3
                    check.explanation = f"Established technical observability practices detected through {', '.join(strategy_signals)} {evidence_refs}. The configuration shows organization-wide standardization and operational adoption; validate training, runbooks, and review processes separately. {manual_questions_l3}"
                # L2: Unified tools and technologies
                elif len(strategy_signals) >= 2:
                    check.current_level = 2
                    check.explanation = f"Unified tools and technologies detected: {', '.join(strategy_signals)} {evidence_refs}. {manual_questions_l3} {manual_questions_l4}"
                # L1: Data collection strategy only
                elif strategy_signals:
                    check.current_level = 1
                    check.explanation = f"Basic data collection strategy with {', '.join(strategy_signals)} {evidence_refs}. Limited evidence of enterprise-wide standardization. {manual_questions_l3}"
                else:
                    check.current_level = 1
                    check.explanation = f"No evidence of an enterprise observability strategy detected {evidence_refs}. {manual_questions_l3}"
                # Integrations are supporting context only and do not change the level.
                if has_omni_integrations:
                    check.explanation += f" CloudWatch Omni has {plural(omni_integrations_check.result['active_integrations'], 'active integration')} connecting it to operational tooling."
