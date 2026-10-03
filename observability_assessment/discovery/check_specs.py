# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Stable built-in discovery definitions; runtime results remain mutable."""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class CheckSpec:
    """Identity and current presentation of a built-in discovery check."""

    key: str
    id: int
    name: str
    category: str
    command: str

    @property
    def categories(self) -> tuple[str, ...]:
        """Category memberships without changing the output string."""
        return tuple(self.category.split(", "))


CHECK_SPECS: tuple[CheckSpec, ...] = (
    CheckSpec(
        key="log_group_source_classification",
        id=1,
        name="What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)?",
        category="Logs",
        command="custom_log_groups_categorization_check",
    ),
    CheckSpec(
        key="log_group_retention",
        id=2,
        name="What percentage of the largest log groups have retention policies configured (example thresholds: security: 90+ days, operational: 30 days, debug: 7 days — actual requirements vary by organization)?",
        category="Logs",
        command="custom_top_log_groups_retention_check",
    ),
    CheckSpec(
        key="logs_insights_queries",
        id=3,
        name="Do you have standardized Logs Insights queries for common troubleshooting scenarios (errors, latency, security events)?",
        category="Logs",
        command="aws logs describe-query-definitions --output json",
    ),
    CheckSpec(
        key="logs_insights_query_history",
        id=4,
        name="Do you have a history of Logs Insights queries being executed?",
        category="Logs",
        command="aws logs describe-queries --output json",
    ),
    CheckSpec(
        key="log_metric_filters",
        id=5,
        name="Have you created metric filters to extract KPIs from logs?",
        category="Logs",
        command="aws logs describe-metric-filters --output json",
    ),
    CheckSpec(
        key="log_subscription_coverage",
        id=6,
        name="What percentage of the largest log groups have subscription filters for real-time processing?",
        category="Logs",
        command="custom_subscription_filters_coverage_check",
    ),
    CheckSpec(
        key="ec2_agent_logs",
        id=7,
        name="What percentage of EC2 instances have the CloudWatch agent installed with both system metrics AND application logs configured?",
        category="Logs",
        command="custom_ec2_cloudwatch_agent_check",
    ),
    CheckSpec(
        key="lambda_json_logging",
        id=8,
        name="What percentage of Lambda functions use JSON structured logging?",
        category="Logs",
        command="custom_lambda_json_logging_check",
    ),
    CheckSpec(
        key="ecs_structured_logging",
        id=9,
        name="What percentage of ECS tasks use structured logging (JSON)?",
        category="Logs",
        command="custom_ecs_task_log_check",
    ),
    CheckSpec(
        key="eks_control_plane_logs",
        id=10,
        name="Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?",
        category="Logs",
        command="custom_eks_control_plane_logs_check",
    ),
    CheckSpec(
        key="eks_observability_addon_logs",
        id=11,
        name="Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?",
        category="Logs",
        command="custom_eks_addons_check",
    ),
    CheckSpec(
        key="log_anomaly_detectors",
        id=12,
        name="Have you enabled anomaly detection?",
        category="Logs",
        command="aws logs list-log-anomaly-detectors --query \"anomalyDetectors[?anomalyDetectorStatus!='PAUSED' && anomalyDetectorStatus!='DELETED' && anomalyDetectorStatus!='FAILED'] | {anomalyDetectors: @}\" --output json",
    ),
    CheckSpec(
        key="log_export_tasks",
        id=13,
        name="Do you have log export tasks configured for archival?",
        category="Logs",
        command="custom_log_export_tasks_per_log_group_check",
    ),
    CheckSpec(
        key="log_centralization",
        id=14,
        name="Have you implemented cross-account and cross-Region log centralization?",
        category="Logs",
        command="custom_log_centralization_analysis_check",
    ),
    CheckSpec(
        key="cross_account_observability",
        id=15,
        name="Are you using CloudWatch cross-account observability?",
        category="Logs",
        command="custom_oam_links_and_sinks_check",
    ),
    CheckSpec(
        key="application_json_logging",
        id=16,
        name="What percentage of application logs use structured JSON format for easier parsing and analysis?",
        category="Logs",
        command="custom_json_structured_logs_check",
    ),
    CheckSpec(
        key="log_field_indexes",
        id=17,
        name="Do you have field index policies configured for faster log queries?",
        category="Logs",
        command="custom_field_indexes_per_log_group_check",
    ),
    CheckSpec(
        key="ec2_detailed_monitoring",
        id=18,
        name="What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?",
        category="Metrics",
        command="aws ec2 describe-instances --query 'Reservations[].Instances[?Monitoring.State==`enabled`]' --output json",
    ),
    CheckSpec(
        key="ecs_clusters",
        id=19,
        name="How many ECS clusters are available to monitor?",
        category="Metrics",
        command="aws ecs list-clusters --output json",
    ),
    CheckSpec(
        key="ecs_container_insights",
        id=20,
        name="Do you have ECS clusters with Container Insights enabled?",
        category="Metrics",
        command="custom_ecs_container_insights_check",
    ),
    CheckSpec(
        key="eks_observability_addon_metrics",
        id=21,
        name="Do you have EKS clusters with the CloudWatch Observability add-on enabled?",
        category="Metrics",
        command="custom_eks_addons_check",
    ),
    CheckSpec(
        key="lambda_insights",
        id=22,
        name="What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?",
        category="Metrics",
        command="custom_lambda_insights_check",
    ),
    CheckSpec(
        key="custom_metric_namespaces",
        id=23,
        name="Are you publishing custom business and application metrics to CloudWatch?",
        category="Metrics",
        command="custom_metrics_namespaces_check",
    ),
    CheckSpec(
        key="cloudwatch_agent_metrics",
        id=24,
        name="Is the CloudWatch agent configured to collect system-level metrics?",
        category="Metrics",
        command="aws cloudwatch list-metrics --namespace CWAgent --recently-active PT3H --output json",
    ),
    CheckSpec(
        key="metric_streams",
        id=25,
        name="Have you configured metric streams for real-time export to third-party tools or data lakes?",
        category="Metrics",
        command="aws cloudwatch list-metric-streams --query \"Entries[?State=='running'] | {Entries: @}\" --output json",
    ),
    CheckSpec(
        key="xray_service_map",
        id=26,
        name="Do you use X-Ray service maps to visualize application architecture?",
        category="Traces",
        command="custom_xray_service_graph_check",
    ),
    CheckSpec(
        key="xray_sampling_rules",
        id=27,
        name="Do you have custom X-Ray sampling rules configured?",
        category="Traces",
        command="custom_xray_sampling_rules_check",
    ),
    CheckSpec(
        key="xray_groups",
        id=28,
        name="Do you have X-Ray groups configured for focused trace analysis?",
        category="Traces",
        command="aws xray get-groups --output json",
    ),
    CheckSpec(
        key="transaction_search",
        id=29,
        name="Do you have Transaction Search enabled?",
        category="Traces",
        command="aws xray get-trace-segment-destination --output json",
    ),
    CheckSpec(
        key="lambda_xray_tracing",
        id=30,
        name="Do your Lambda functions have X-Ray tracing enabled?",
        category="Traces",
        command="aws lambda list-functions --query 'Functions[?TracingConfig.Mode==`Active`]' --output json",
    ),
    CheckSpec(
        key="xray_insights",
        id=31,
        name="Do you have X-Ray Insights configured for anomaly detection?",
        category="Traces",
        command="custom_xray_insights_check",
    ),
    CheckSpec(
        key="xray_annotations",
        id=32,
        name="Do your traces contain custom annotations indicating manual instrumentation?",
        category="Traces",
        command="custom_xray_custom_annotations_check",
    ),
    CheckSpec(
        key="cloudwatch_dashboards",
        id=33,
        name="Do you have CloudWatch dashboards for visualizing metrics and logs?",
        category="Dashboards, Logs, Metrics",
        command="aws cloudwatch list-dashboards --output json",
    ),
    CheckSpec(
        key="cloudwatch_alarms",
        id=34,
        name="Do you have CloudWatch alarms configured for your resources?",
        category="Alarms",
        command="custom_cloudwatch_alarms_check",
    ),
    CheckSpec(
        key="composite_alarms",
        id=35,
        name="Do you use composite alarms to reduce alarm noise?",
        category="Alarms",
        command="aws cloudwatch describe-alarms --alarm-types CompositeAlarm --output json",
    ),
    CheckSpec(
        key="alarm_sns_actions",
        id=36,
        name="Do your alarms send notifications to SNS topics?",
        category="Alarms",
        command="custom_alarm_sns_configuration_check",
    ),
    CheckSpec(
        key="alarm_anomaly_detection",
        id=37,
        name="Do you use anomaly detection models for adaptive alarming?",
        category="Alarms",
        command="custom_anomaly_detection_bands_check",
    ),
    CheckSpec(
        key="resource_tags",
        id=38,
        name="Do you use resource tags for organizing and managing AWS resources?",
        category="Organization",
        command="aws resourcegroupstaggingapi get-resources --query 'ResourceTagMappingList[?length(Tags) > `0`] | {ResourceTagMappingList: @}' --output json",
    ),
    CheckSpec(
        key="synthetics_canaries",
        id=39,
        name="Do you use CloudWatch Synthetics to monitor application endpoints?",
        category="Organization",
        command="aws synthetics describe-canaries --output json",
    ),
    CheckSpec(
        key="rum_app_monitors",
        id=40,
        name="Do you use CloudWatch RUM to monitor real user experiences?",
        category="Organization",
        command="aws rum list-app-monitors --output json",
    ),
    CheckSpec(
        key="alarm_opsitem_actions",
        id=41,
        name="Do you have any Systems Manager OpsCenter actions configured with your alarms?",
        category="Organization",
        command="custom_alarm_opsitem_actions_check",
    ),
    CheckSpec(
        key="devops_agent_spaces",
        id=42,
        name="Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
        category="Organization",
        command="custom_devops_agent_spaces_check",
    ),
    CheckSpec(
        key="alarm_lambda_actions",
        id=43,
        name="Do you have any Lambda actions configured with your alarms?",
        category="Alarms",
        command="custom_alarm_lambda_actions_check",
    ),
    CheckSpec(
        key="alarm_investigation_actions",
        id=44,
        name="Have you configured CloudWatch Investigations actions for any alarms?",
        category="Alarms",
        command="custom_alarm_investigations_actions_check",
    ),
    CheckSpec(
        key="alarm_ec2_actions",
        id=45,
        name="Do you have any EC2 actions configured with your alarms?",
        category="Alarms",
        command="custom_alarm_ec2_actions_check",
    ),
    CheckSpec(
        key="dashboard_variables",
        id=46,
        name="Do you have dashboards configured with variables?",
        category="Dashboards",
        command="custom_dashboard_variables_check",
    ),
    CheckSpec(
        key="application_signals_services",
        id=47,
        name="Do you use CloudWatch Application Signals to monitor application services?",
        category="Metrics, Traces",
        command="custom_app_signals_list_services_check",
    ),
    CheckSpec(
        key="service_level_objectives",
        id=48,
        name="Have you defined Service Level Objectives (SLOs) for critical application services?",
        category="Metrics, Organization",
        command="aws application-signals list-service-level-objectives --output json",
    ),
    CheckSpec(
        key="log_group_tags",
        id=49,
        name="Do your log groups have resource tags for retention governance and metadata-based search?",
        category="Logs",
        command="custom_log_group_tags_check",
    ),
    CheckSpec(
        key="stale_log_groups",
        id=50,
        name="Do you have stale or unused log groups that are collecting data but not being used?",
        category="Logs",
        command="custom_stale_log_groups_check",
    ),
    CheckSpec(
        key="cloudwatch_omni_spaces",
        id=51,
        name="Do you use CloudWatch Omni spaces for unified access to logs, metrics, and traces?",
        category="Organization",
        command="custom_cloudwatch_omni_spaces_check",
    ),
    CheckSpec(
        key="cloudwatch_omni_integrations",
        id=52,
        name="Have you connected CloudWatch Omni integrations (Context Graph resource discovery, Slack, external agents)?",
        category="Organization",
        command="custom_cloudwatch_omni_integrations_check",
    ),
)


def _validate_specs() -> None:
    if len(CHECK_SPECS) != 52:
        raise ValueError("Expected exactly 52 built-in discovery checks")
    if [spec.id for spec in CHECK_SPECS] != list(range(1, 53)):
        raise ValueError("Built-in discovery IDs must be 1 through 52 in order")
    if len({spec.key for spec in CHECK_SPECS}) != len(CHECK_SPECS):
        raise ValueError("Built-in discovery keys must be unique")
    if len({(spec.name, spec.command) for spec in CHECK_SPECS}) != len(CHECK_SPECS):
        raise ValueError("Built-in discovery names and commands must be unique")
    if any(not spec.key or not spec.categories for spec in CHECK_SPECS):
        raise ValueError("Built-in discovery keys and categories are required")


_validate_specs()
CHECK_SPECS_BY_KEY = MappingProxyType({spec.key: spec for spec in CHECK_SPECS})
CHECK_SPECS_BY_ID = MappingProxyType({spec.id: spec for spec in CHECK_SPECS})
