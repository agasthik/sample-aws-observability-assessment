# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Assessment scoring for traces."""

from observability_assessment.text import plural


class TracesScoringMixin:
    """Scoring methods that operate on ``self.results``."""

    def assess_traces_maturity(self):
        """Assess traces maturity based on discovery checks"""
        traces_checks = [
            c for c in self.results.assessment_checks if c.category == "Traces"
        ]

        for check in traces_checks:
            if check.question_id == 8:  # How do you collect traces?
                xray_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use X-Ray service maps to visualize application architecture?"
                    ),
                    None,
                )
                lambda_tracing_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do your Lambda functions have X-Ray tracing enabled?"
                    ),
                    None,
                )
                sampling_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have custom X-Ray sampling rules configured?"
                    ),
                    None,
                )
                groups_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have X-Ray groups configured for focused trace analysis?"
                    ),
                    None,
                )
                transaction_search_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "Do you have Transaction Search enabled?"
                    ),
                    None,
                )
                annotations_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do your traces contain custom annotations indicating manual instrumentation?"
                    ),
                    None,
                )

                check.evidence_check_ids = [
                    c.id
                    for c in [
                        xray_check,
                        lambda_tracing_check,
                        sampling_check,
                        groups_check,
                        transaction_search_check,
                        annotations_check,
                    ]
                    if c
                ]

                has_service_map = (
                    xray_check
                    and xray_check.result
                    and xray_check.result.get("Services")
                )
                has_sampling = (
                    sampling_check
                    and sampling_check.result
                    and sampling_check.result.get("SamplingRuleRecords")
                )
                has_groups = (
                    groups_check
                    and groups_check.result
                    and groups_check.result.get("Groups")
                )
                has_lambda_tracing = (
                    lambda_tracing_check
                    and lambda_tracing_check.result
                    and isinstance(lambda_tracing_check.result, list)
                    and len(lambda_tracing_check.result) > 0
                )
                has_transaction_search = (
                    transaction_search_check
                    and isinstance(transaction_search_check.result, dict)
                    and transaction_search_check.result.get("Destination")
                    == "CloudWatchLogs"
                    and transaction_search_check.result.get("Status") == "ACTIVE"
                )
                has_custom_annotations = (
                    annotations_check
                    and isinstance(annotations_check.result, dict)
                    and annotations_check.result.get(
                        "traces_with_custom_annotations", 0
                    )
                    > 0
                )

                if (
                    has_transaction_search
                    and has_service_map
                    and has_sampling
                    and has_groups
                ):
                    service_count = len(xray_check.result.get("Services", []))
                    rule_count = len(
                        sampling_check.result.get("SamplingRuleRecords", [])
                    )
                    group_count = len(groups_check.result.get("Groups", []))
                    check.current_level = 4
                    check.explanation = f"Advanced tracing with Transaction Search enabled (Check #{transaction_search_check.id}), X-Ray service map showing {plural(service_count, 'service')} (Check #{xray_check.id}), {plural(rule_count, 'sampling rule')} (Check #{sampling_check.id}), and {plural(group_count, 'X-Ray group')} for focused analysis (Check #{groups_check.id}). This provides automatic injection with proactive alerts, complete span visibility, optimized trace collection, and targeted trace filtering across distributed services."
                elif (
                    has_service_map
                    and has_sampling
                    and (has_groups or has_transaction_search)
                ):
                    service_count = len(xray_check.result.get("Services", []))
                    rule_count = len(
                        sampling_check.result.get("SamplingRuleRecords", [])
                    )
                    check.current_level = 3
                    if has_groups:
                        group_count = len(groups_check.result.get("Groups", []))
                        check.explanation = f"Comprehensive tracing infrastructure with X-Ray service map showing {plural(service_count, 'service')} (Check #{xray_check.id}), {plural(rule_count, 'sampling rule')} (Check #{sampling_check.id}), and {plural(group_count, 'X-Ray group')} (Check #{groups_check.id}). This provides end-to-end visibility with optimized trace collection, focused trace analysis, and correlation capabilities across distributed services."
                    else:
                        check.explanation = f"Comprehensive tracing infrastructure with Transaction Search enabled (Check #{transaction_search_check.id}), X-Ray service map showing {plural(service_count, 'service')} (Check #{xray_check.id}), and {plural(rule_count, 'sampling rule')} (Check #{sampling_check.id}). This provides end-to-end visibility with complete span coverage and optimized trace collection across distributed services."
                elif (has_service_map or has_lambda_tracing) and (
                    has_custom_annotations or has_sampling
                ):
                    check.current_level = 2
                    capabilities = []
                    if has_service_map:
                        capabilities.append(
                            f"X-Ray service map with {plural(len(xray_check.result.get('Services', [])), 'service')} (Check #{xray_check.id})"
                        )
                    if has_lambda_tracing:
                        capabilities.append(
                            f"{plural(len(lambda_tracing_check.result), 'Lambda function')} with tracing (Check #{lambda_tracing_check.id})"
                        )
                    if has_custom_annotations:
                        keys = annotations_check.result.get(
                            "custom_annotation_keys", []
                        )
                        capabilities.append(
                            f"custom annotations [{', '.join(keys[:5])}] (Check #{annotations_check.id})"
                        )
                    if has_sampling:
                        capabilities.append(
                            f"{plural(len(sampling_check.result.get('SamplingRuleRecords', [])), 'sampling rule')} (Check #{sampling_check.id})"
                        )
                    check.explanation = f"Auto and manual instrumentation detected: {', '.join(capabilities)}. Custom annotations or sampling rules indicate developers have gone beyond auto-instrumentation."
                elif has_service_map or has_lambda_tracing:
                    check.current_level = 1
                    if has_service_map:
                        service_count = len(xray_check.result.get("Services", []))
                        check.explanation = f"Auto-instrumented tracing with X-Ray service map tracking {plural(service_count, 'service')} (Check #{xray_check.id}). No evidence of manual instrumentation (custom annotations or sampling rules)."
                    else:
                        traced_functions = (
                            len(lambda_tracing_check.result)
                            if isinstance(lambda_tracing_check.result, list)
                            else 0
                        )
                        check.explanation = f"Auto-instrumented tracing for {plural(traced_functions, 'Lambda function')} (Check #{lambda_tracing_check.id}). No evidence of manual instrumentation."
                else:
                    check.current_level = 1
                    check.explanation = "Limited or no distributed tracing detected. Basic auto-instrumented SDKs may be present but without comprehensive trace collection."

            elif check.question_id == 9:  # How do you use traces?
                xray_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use X-Ray service maps to visualize application architecture?"
                    ),
                    None,
                )
                insights_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have X-Ray Insights configured for anomaly detection?"
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
                groups_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have X-Ray groups configured for focused trace analysis?"
                    ),
                    None,
                )
                transaction_search_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name == "Do you have Transaction Search enabled?"
                    ),
                    None,
                )
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
                slo_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Have you defined Service Level Objectives (SLOs) for critical application services?"
                    ),
                    None,
                )
                dashboards_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you have CloudWatch dashboards for visualizing metrics and logs?"
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
                composite_check = next(
                    (
                        c
                        for c in self.results.discovery_checks
                        if c.name
                        == "Do you use composite alarms to reduce alarm noise?"
                    ),
                    None,
                )

                all_checks = [
                    xray_check,
                    insights_check,
                    app_signals_check,
                    groups_check,
                    transaction_search_check,
                    rum_check,
                    synthetics_check,
                    slo_check,
                    dashboards_check,
                    alarms_check,
                    composite_check,
                ]
                check.evidence_check_ids = [c.id for c in all_checks if c]

                has_service_map = (
                    xray_check
                    and xray_check.result
                    and xray_check.result.get("Services")
                )
                has_insights = (
                    insights_check
                    and insights_check.result
                    and insights_check.result.get("insights_enabled_groups", 0) > 0
                )
                has_app_signals = (
                    app_signals_check
                    and app_signals_check.result
                    and app_signals_check.result.get("Services")
                )
                has_groups = (
                    groups_check
                    and groups_check.result
                    and groups_check.result.get("Groups")
                )
                has_transaction_search = (
                    transaction_search_check
                    and isinstance(transaction_search_check.result, dict)
                    and transaction_search_check.result.get("Destination")
                    == "CloudWatchLogs"
                    and transaction_search_check.result.get("Status") == "ACTIVE"
                )
                has_rum = (
                    rum_check
                    and rum_check.result
                    and rum_check.result.get("AppMonitorSummaries")
                )
                has_synthetics = (
                    synthetics_check
                    and synthetics_check.result
                    and synthetics_check.result.get("Canaries")
                )
                has_slos = (
                    slo_check
                    and slo_check.result
                    and slo_check.result.get("SloSummaries")
                )
                has_dashboards = (
                    dashboards_check
                    and dashboards_check.result
                    and dashboards_check.result.get("DashboardEntries")
                )
                has_composite = (
                    composite_check
                    and isinstance(composite_check.result, dict)
                    and composite_check.result.get("CompositeAlarms")
                )

                # L4: Cross-boundary insights with proactive root cause — App Signals + SLOs or App Signals + Transaction Search + correlation evidence
                if has_app_signals and has_slos:
                    service_count = len(app_signals_check.result.get("Services", []))
                    slo_count = len(slo_check.result.get("SloSummaries", []))
                    check.current_level = 4
                    check.explanation = f"Cross-boundary trace insights with Application Signals monitoring {plural(service_count, 'service')} (Check #{app_signals_check.id}) and {plural(slo_count, 'SLO')} defined (Check #{slo_check.id}), enabling proactive root cause identification across application boundaries with automated issue detection and business-aligned reliability targets."
                elif (
                    has_app_signals
                    and has_transaction_search
                    and (has_insights or has_composite)
                ):
                    service_count = len(app_signals_check.result.get("Services", []))
                    extras = []
                    if has_insights:
                        extras.append(
                            f"X-Ray Insights on {plural(insights_check.result.get('insights_enabled_groups', 0), 'group')} (Check #{insights_check.id})"
                        )
                    if has_composite:
                        extras.append(
                            f"{plural(len(composite_check.result.get('CompositeAlarms', [])), 'composite alarm')} (Check #{composite_check.id})"
                        )
                    check.current_level = 4
                    check.explanation = f"Cross-boundary trace insights with Application Signals monitoring {plural(service_count, 'service')} (Check #{app_signals_check.id}), Transaction Search (Check #{transaction_search_check.id}), and {', '.join(extras)}. This provides proactive root cause identification with complete span visibility across distributed services."
                # L3: 360 view — traces + logs + metrics correlation and anomaly detection
                elif has_app_signals and has_transaction_search:
                    service_count = len(app_signals_check.result.get("Services", []))
                    check.current_level = 3
                    check.explanation = f"Comprehensive trace analysis with Application Signals monitoring {plural(service_count, 'service')} (Check #{app_signals_check.id}) and Transaction Search enabled (Check #{transaction_search_check.id}), providing a 360-degree view combining traces, logs, and metrics for correlation. Consider adding SLOs or X-Ray Insights for proactive root cause identification."
                elif has_app_signals or (
                    has_service_map
                    and (has_insights or has_groups or has_transaction_search)
                ):
                    parts = []
                    if has_app_signals:
                        parts.append(
                            f"Application Signals monitoring {plural(len(app_signals_check.result.get('Services', [])), 'service')} (Check #{app_signals_check.id})"
                        )
                    if has_transaction_search:
                        parts.append(
                            f"Transaction Search (Check #{transaction_search_check.id})"
                        )
                    if has_insights:
                        parts.append(
                            f"X-Ray Insights on {plural(insights_check.result.get('insights_enabled_groups', 0), 'group')} (Check #{insights_check.id})"
                        )
                    if has_groups:
                        parts.append(
                            f"{plural(len(groups_check.result.get('Groups', [])), 'X-Ray group')} (Check #{groups_check.id})"
                        )
                    if has_service_map:
                        parts.append(
                            f"service map with {plural(len(xray_check.result.get('Services', [])), 'service')} (Check #{xray_check.id})"
                        )
                    check.current_level = 3
                    check.explanation = f"Trace correlation with {', '.join(parts)}. This provides a 360-degree view for correlation and anomaly detection across infrastructure and applications."
                # L2: Analyze and troubleshoot with traces
                elif has_service_map:
                    service_count = len(xray_check.result.get("Services", []))
                    extras = []
                    if has_rum:
                        extras.append(f"RUM (Check #{rum_check.id})")
                    if has_synthetics:
                        extras.append(f"Synthetics (Check #{synthetics_check.id})")
                    if has_dashboards:
                        extras.append(f"dashboards (Check #{dashboards_check.id})")
                    extra_str = f" with {', '.join(extras)}" if extras else ""
                    check.current_level = 2
                    check.explanation = f"Active trace analysis using X-Ray service map with {plural(service_count, 'service')} (Check #{xray_check.id}){extra_str}, enabling troubleshooting and performance analysis based on captured trace information and service dependencies."
                else:
                    check.current_level = 1
                    check.explanation = "Basic trace collection without advanced analysis capabilities. Traces may be collected but not actively used for systematic troubleshooting or performance optimization."
