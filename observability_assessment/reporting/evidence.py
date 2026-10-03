# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Detailed evidence text for discovery checks."""

import html

from observability_assessment.models import DiscoveryCheck
from observability_assessment.text import plural


def esc(value) -> str:
    """HTML-escape an AWS-sourced value for inclusion in evidence markup."""
    return html.escape(str(value))


class EvidenceReportingMixin:
    def generate_detailed_evidence(self, check: DiscoveryCheck) -> str:
        """Generate detailed evidence with summary and expandable details"""
        base_info = f"Account: {self.results.account_id}, Region: {self.region}"

        if not check.result:
            return "No resources found"

        if check.name == "Do you have Transaction Search enabled?":
            destination = check.result.get("Destination", "Unknown")
            status = check.result.get("Status", "Unknown")
            if destination == "CloudWatchLogs" and status == "ACTIVE":
                return "Transaction Search is active: trace segments are sent to CloudWatch Logs"
            return f"Transaction Search is not active (segment destination: {destination}, status: {status})"

        # Handle specific checks first to avoid generic handler conflicts
        if (
            check.name
            == "Have you configured metric streams for real-time export to third-party tools or data lakes?"
        ):
            entries = check.result.get("Entries", [])
            if entries:
                summary = f"Found {plural(len(entries), 'metric stream')}"

                # Create detailed breakdown
                details = ""
                for i, stream in enumerate(entries, 1):
                    name = stream.get("Name", "Unknown")
                    state = stream.get("State", "Unknown")
                    output_format = stream.get("OutputFormat", "Unknown")
                    firehose_arn = stream.get("FirehoseArn", "Unknown")
                    creation_date = stream.get("CreationDate", "Unknown")

                    details += f"{i}. <strong>{name}</strong><br>"
                    details += f"   State: {state}<br>"
                    details += f"   Output Format: {output_format}<br>"
                    details += f"   Firehose: {firehose_arn.split('/')[-1] if '/' in str(firehose_arn) else firehose_arn}<br>"
                    details += f"   Created: {creation_date}<br><br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No metric streams found"

        elif check.name == "Do you use composite alarms to reduce alarm noise?":
            composite_alarms = check.result.get("CompositeAlarms", [])
            if composite_alarms:
                summary = f"Found {plural(len(composite_alarms), 'composite alarm')}"

                # Create detailed breakdown
                details = ""
                for i, alarm in enumerate(composite_alarms, 1):
                    alarm_name = alarm.get("AlarmName", "Unknown")
                    state_value = alarm.get("StateValue", "Unknown")
                    alarm_rule = alarm.get("AlarmRule", "No rule")
                    actions_enabled = alarm.get("ActionsEnabled", False)
                    alarm_actions = alarm.get("AlarmActions", [])

                    details += f"{i}. <strong>{alarm_name}</strong><br>"
                    details += f"   State: {state_value}<br>"
                    details += f"   Rule: {alarm_rule}<br>"
                    details += f"   Actions Enabled: {actions_enabled}<br>"
                    if alarm_actions:
                        details += f"   Actions: {len(alarm_actions)} configured<br>"
                        for j, action in enumerate(alarm_actions[:3], 1):
                            action_type = (
                                "SNS"
                                if "sns:" in action
                                else "SSM"
                                if "ssm:" in action
                                else "Other"
                            )
                            details += (
                                f"     {j}. {action_type}: {action.split(':')[-1]}<br>"
                            )
                    details += "<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No composite alarms found"

        elif (
            check.name
            == "What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?"
        ):
            if check.result:
                total_functions = check.result.get("total_functions", 0)
                insights_functions = check.result.get("insights_functions", 0)
                functions_with_insights = check.result.get(
                    "functions_with_insights", []
                )

                summary = f"{insights_functions}/{total_functions} Lambda functions have Lambda Insights enabled"

                if insights_functions > 0:
                    # Create detailed breakdown
                    details = f"<strong>Lambda Functions with Insights Enabled ({insights_functions}):</strong><br>"
                    for i, func_name in enumerate(functions_with_insights, 1):
                        details += f"{i}. {func_name}<br>"

                    details += f"<br><strong>Functions without Insights ({total_functions - insights_functions}):</strong><br>"
                    details += f"Total functions without Lambda Insights: {total_functions - insights_functions}<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"

                return summary
            return "No Lambda functions found"

        elif (
            check.name
            == "Are you publishing custom business and application metrics to CloudWatch?"
        ):
            if check.result:
                custom_namespaces = check.result.get("custom_namespaces", [])
                total_custom_metrics = check.result.get("total_custom_metrics", 0)
                sample_metrics = check.result.get("sample_metrics", [])

                if custom_namespaces:
                    summary = f"Found {plural(len(custom_namespaces), 'custom namespace')} with {plural(total_custom_metrics, 'total metric')}"

                    # Create detailed breakdown
                    details = f"<strong>Custom Metrics Namespaces ({len(custom_namespaces)}):</strong><br>"
                    for i, namespace in enumerate(custom_namespaces, 1):
                        details += f"{i}. {namespace}<br>"

                    if sample_metrics:
                        details += f"<br><strong>Sample Custom Metrics ({len(sample_metrics)}):</strong><br>"
                        for i, metric in enumerate(sample_metrics, 1):
                            namespace = metric.get("Namespace", "Unknown")
                            metric_name = metric.get("MetricName", "Unknown")
                            dimensions = metric.get("Dimensions", [])
                            dim_info = (
                                f" | Dimensions: {len(dimensions)}"
                                if dimensions
                                else ""
                            )
                            details += f"{i}. {namespace}/{metric_name}{dim_info}<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"

                return f"Found {plural(len(custom_namespaces), 'custom namespace')} with {plural(total_custom_metrics, 'metric')}"
            return "No custom metrics found"

        elif check.name == "Have you created metric filters to extract KPIs from logs?":
            command_info = f"Command: {check.command}"
            metric_filters = check.result.get("metricFilters", [])
            if metric_filters:
                summary = f"Found {plural(len(metric_filters), 'metric filter')}"

                # Create detailed breakdown
                details = ""
                for i, mf in enumerate(metric_filters, 1):
                    filter_name = mf.get("filterName", "Unnamed")
                    log_group = mf.get("logGroupName", "Unknown")
                    pattern = mf.get("filterPattern", "No pattern")
                    metric_transformations = mf.get("metricTransformations", [])

                    details += f"{i}. <strong>{filter_name}</strong><br>"
                    details += f"   Log Group: {log_group}<br>"
                    details += f"   Pattern: {pattern}<br>"

                    if metric_transformations:
                        for j, mt in enumerate(metric_transformations):
                            metric_name = mt.get("metricName", "Unknown")
                            metric_namespace = mt.get("metricNamespace", "Unknown")
                            metric_value = mt.get("metricValue", "Unknown")
                            details += f"   Metric {j + 1}: {metric_namespace}/{metric_name} = {metric_value}<br>"
                    else:
                        details += "   No metric transformations<br>"
                    details += "<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"{command_info} | No metric filters found - no log groups are configured to extract metrics from log events"

        elif (
            check.name
            == "What percentage of the largest log groups have subscription filters for real-time processing?"
        ):
            if check.result:
                total_groups = check.result.get("total_log_groups", 0)
                groups_with_filters = check.result.get(
                    "groups_with_subscription_filters", 0
                )
                sample_groups = check.result.get("sample_filtered_groups", [])
                filter_details = check.result.get("subscription_filter_details", [])

                if groups_with_filters > 0:
                    summary = f"Found {groups_with_filters}/{total_groups} log groups with subscription filters"

                    # Create detailed breakdown
                    details = ""
                    if filter_details:
                        for i, detail in enumerate(filter_details, 1):
                            log_group = detail.get("log_group", "Unknown")
                            filter_name = detail.get("filter_name", "Unknown")
                            destination_arn = detail.get("destination_arn", "Unknown")
                            filter_pattern = detail.get("filter_pattern", "No pattern")

                            details += f"{i}. <strong>{log_group}</strong><br>"
                            details += f"   Filter Name: {filter_name}<br>"
                            details += f"   Destination: {destination_arn}<br>"
                            details += f"   Pattern: {filter_pattern}<br><br>"
                    else:
                        # Fallback to sample groups if no detailed info
                        for i, group in enumerate(sample_groups, 1):
                            details += f"{i}. {group}<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return f"Checked {plural(total_groups, 'log group')} - {groups_with_filters}/{total_groups} have subscription filters"
            return "No log groups checked for subscription filters"

        elif (
            check.name
            == "What percentage of EC2 instances have the CloudWatch agent installed with both system metrics AND application logs configured?"
        ):
            instances = check.result.get("instances", [])
            ssm_instances = check.result.get("ssm_instances", [])
            cw_agent_instances = check.result.get("cw_agent_instances", [])
            logging_configured_instances = check.result.get(
                "logging_configured_instances", []
            )

            total_instances = len(instances)
            ssm_count = len(ssm_instances)
            cw_agent_count = len(cw_agent_instances)
            logging_count = len(logging_configured_instances)

            # The CW Agent / Logging checks probe only a sample of SSM-managed
            # instances (SSM send-command is slow). Disclose the sampling so the
            # counts below aren't misread as covering every SSM instance.
            sampled_count = check.result.get("ssm_sampled_count", ssm_count)
            sample_limit = check.result.get("ssm_sample_limit")
            is_sampled = ssm_count > sampled_count

            if total_instances > 0:
                cw_denominator = sampled_count if is_sampled else ssm_count
                summary = f"Total: {plural(total_instances, 'instance')} | SSM: {ssm_count}/{total_instances} | CW Agent: {cw_agent_count}/{cw_denominator} | Logging: {logging_count}/{cw_denominator}"
                if is_sampled:
                    summary += f" | NOTE: CW Agent & Logging measured on a sample of {sampled_count} of {ssm_count} SSM-managed instances (limit {sample_limit}); percentages are indicative, not exhaustive"

                # Create detailed breakdown
                details = ""
                details += (
                    f"<strong>All EC2 Instances ({total_instances}):</strong><br>"
                )
                for i, instance in enumerate(instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(instances) > 10:
                    details += (
                        f"... and {plural(len(instances) - 10, 'more instance')}<br>"
                    )

                details += (
                    f"<br><strong>SSM Managed Instances ({ssm_count}):</strong><br>"
                )
                for i, instance in enumerate(ssm_instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(ssm_instances) > 10:
                    details += f"... and {plural(len(ssm_instances) - 10, 'more instance')}<br>"

                if is_sampled:
                    details += f"<br><em>Note: CloudWatch agent and log-collection status below was probed on only the first {sampled_count} of {ssm_count} SSM-managed instances (performance limit {sample_limit}). Counts are a sample, not a full census.</em><br>"

                sample_scope = f" of {sampled_count} sampled" if is_sampled else ""
                details += f"<br><strong>CloudWatch agent Running ({cw_agent_count}{sample_scope}):</strong><br>"
                for i, instance in enumerate(cw_agent_instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(cw_agent_instances) > 10:
                    details += f"... and {plural(len(cw_agent_instances) - 10, 'more instance')}<br>"

                details += (
                    f"<br><strong>Logging Configured ({logging_count}):</strong><br>"
                )
                for i, instance in enumerate(logging_configured_instances[:10], 1):
                    details += f"{i}. {instance}<br>"
                if len(logging_configured_instances) > 10:
                    details += f"... and {plural(len(logging_configured_instances) - 10, 'more instance')}<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No EC2 instances found"

        elif (
            check.name
            == "What percentage of Lambda functions use JSON structured logging?"
        ):
            if isinstance(check.result, dict):
                total = check.result.get("total_functions", 0)
                json_count = check.result.get("json_logging_count", 0)
                functions = check.result.get("functions_with_json", [])

                if total > 0:
                    percentage = (json_count / total) * 100
                    summary = f"Lambda functions: {total} | JSON logging: {json_count}/{total} ({percentage:.1f}%)"
                    if functions:
                        details = "<br>".join(functions[:10])
                        if len(functions) > 10:
                            details += f"<br>... and {len(functions) - 10} more"
                        return f"{summary}<details><summary>Show Functions</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                    return summary
            return "No Lambda functions found"

        elif (
            check.name == "What percentage of ECS tasks use structured logging (JSON)?"
        ):
            if check.result:
                clusters = check.result.get("clusters", [])
                running_tasks = check.result.get("running_tasks", [])
                tasks_with_logging = check.result.get("tasks_with_logging", [])
                logging_configs = check.result.get("logging_configs", [])

                if running_tasks:
                    summary = f"ECS clusters: {len(clusters)} | Running tasks: {len(running_tasks)} | Tasks with logging: {len(tasks_with_logging)}/{len(running_tasks)}"

                    # Create detailed breakdown
                    details = ""
                    details += f"<strong>ECS Clusters ({len(clusters)}):</strong><br>"
                    for i, cluster in enumerate(clusters, 1):
                        details += f"{i}. {cluster}<br>"

                    details += f"<br><strong>Running Tasks ({len(running_tasks)}):</strong><br>"
                    for i, task in enumerate(running_tasks[:10], 1):
                        details += f"{i}. {task}<br>"
                    if len(running_tasks) > 10:
                        details += f"... and {plural(len(running_tasks) - 10, 'more task')}<br>"

                    details += f"<br><strong>Tasks with Logging ({len(tasks_with_logging)}):</strong><br>"
                    for i, task in enumerate(tasks_with_logging[:10], 1):
                        details += f"{i}. {task}<br>"
                    if len(tasks_with_logging) > 10:
                        details += f"... and {plural(len(tasks_with_logging) - 10, 'more task')}<br>"

                    if logging_configs:
                        details += f"<br><strong>Logging Configurations ({len(logging_configs)}):</strong><br>"
                        for i, config in enumerate(logging_configs, 1):
                            task_def = config.get("taskDefinition", "Unknown")
                            containers = config.get("containers", [])
                            details += (
                                f"{i}. <strong>Task Definition:</strong> {task_def}<br>"
                            )
                            for j, container in enumerate(containers, 1):
                                container_name = container.get("container", "Unknown")
                                log_driver = container.get("logDriver", "none")
                                log_group = container.get("options", {}).get(
                                    "awslogs-group", "N/A"
                                )
                                details += f"   Container {j}: {container_name} | Driver: {log_driver} | Group: {log_group}<br>"
                            details += "<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return "No running ECS tasks found"
            return "No ECS task log configuration data available"

        elif (
            check.name
            == "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?"
        ):
            if check.result and isinstance(check.result, dict):
                total = check.result.get("total_clusters", 0)
                obs_count = check.result.get("observability_clusters", 0)
                clusters = check.result.get("clusters_with_observability", [])
                if total == 0:
                    return "No EKS clusters found in this account"
                issues = check.result.get("clusters_with_addon_issues", [])
                summary = f"{obs_count}/{total} EKS clusters have the CloudWatch Observability add-on active with Container Insights enabled"
                if clusters or issues:
                    details = ""
                    if clusters:
                        details += (
                            "<strong>Clusters with add-on active:</strong><br>"
                            + "<br>".join(clusters)
                        )
                    if issues:
                        if details:
                            details += "<br><br>"
                        details += (
                            "<strong>Clusters with add-on issues:</strong><br>"
                            + "<br>".join(
                                f"{i['cluster']} (status: {i['status']}, Container Insights: {'on' if i['container_insights_enabled'] else 'off'})"
                                for i in issues
                            )
                        )
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return summary
            return "No EKS clusters found in this account"

        elif check.name == "Have you enabled anomaly detection?":
            anomaly_detectors = check.result.get("anomalyDetectors", [])
            if anomaly_detectors:
                summary = (
                    f"Found {plural(len(anomaly_detectors), 'log anomaly detector')}"
                )
                details = []
                for detector in anomaly_detectors[:5]:  # Show first 5 detectors
                    detector_name = detector.get("detectorName", "Unknown")
                    status = detector.get("anomalyDetectorStatus", "Unknown")
                    log_groups = detector.get("logGroupArnList", [])
                    log_group_names = [lg.split(":")[-1] for lg in log_groups]
                    details.append(
                        f"Name: {detector_name}<br>Status: {status}<br>Log Groups: {', '.join(log_group_names[:2])}<br>"
                    )

                details_html = "<br>".join(details)
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details_html}</div></details>"
            return "No log anomaly detectors found"

        elif check.name == "Do you have log export tasks configured for archival?":
            if check.result:
                total_groups = check.result.get("total_log_groups", 0)
                exported_groups = check.result.get("exported_log_groups", 0)
                sample_groups = check.result.get("sample_exported_groups", [])
                export_details = check.result.get("export_task_details", [])

                if exported_groups > 0:
                    summary = f"Found {exported_groups}/{total_groups} log groups with export history"

                    # Create detailed breakdown
                    details = f"<strong>Log Groups with Export History ({exported_groups}):</strong><br>"

                    if export_details:
                        for i, detail in enumerate(export_details, 1):
                            log_group = detail.get("log_group", "Unknown")
                            task_count = detail.get("task_count", 0)
                            latest_task = detail.get("latest_task", {})

                            details += f"{i}. <strong>{log_group}</strong><br>"
                            details += f"   Export Tasks: {task_count}<br>"

                            if latest_task:
                                task_id = latest_task.get("taskId", "Unknown")
                                status = latest_task.get("status", "Unknown")
                                destination = latest_task.get("destination", "Unknown")
                                from_time = latest_task.get("from", "Unknown")
                                to_time = latest_task.get("to", "Unknown")

                                details += f"   Latest Task: {task_id}<br>"
                                details += f"   Status: {status}<br>"
                                details += f"   Destination: {destination}<br>"
                                details += (
                                    f"   Time Range: {from_time} to {to_time}<br>"
                                )
                            details += "<br>"
                    else:
                        # Fallback to sample groups
                        for i, group in enumerate(sample_groups, 1):
                            details += f"{i}. {group}<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return f"Checked {plural(total_groups, 'log group')} - {exported_groups}/{total_groups} have export history"
            return "No log groups checked for export tasks"

        elif (
            check.name
            == "Have you implemented cross-account and cross-Region log centralization?"
        ):
            if check.result:
                patterns = check.result.get("centralization_patterns", [])
                account_type = check.result.get("account_type", "Unknown")
                org_status = check.result.get("organization_status", "Unknown")

                summary = f"Account type: {account_type} | Org status: {org_status}"

                if patterns:
                    summary += (
                        f" | Found {plural(len(patterns), 'centralization pattern')}"
                    )

                    # Create detailed breakdown
                    details = "<strong>Account Information:</strong><br>"
                    details += f"Account type: {account_type}<br>"
                    details += f"Organization Status: {org_status}<br><br>"

                    details += f"<strong>Centralization Patterns ({len(patterns)}):</strong><br>"
                    for i, pattern in enumerate(patterns, 1):
                        details += f"{i}. {pattern}<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    summary += " | No centralization patterns detected"

                return summary
            return "No centralization analysis data available"

        elif check.name == "Are you using CloudWatch cross-account observability?":
            if check.result:
                account_type = check.result.get("account_type", "Unknown")
                links_count = check.result.get("links_count", 0)
                sinks_count = check.result.get("sinks_count", 0)
                config_details = check.result.get("configuration_details", [])

                summary = f"Account type: {account_type}"
                if links_count > 0 or sinks_count > 0:
                    summary += f" | Links: {links_count}, Sinks: {sinks_count}"
                    if config_details:
                        details_text = "<br>".join(config_details)
                        return f"{summary}<details><summary>Show Configuration Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details_text}</div></details>"
                return summary
            return "OAM configuration check failed"

        elif (
            check.name
            == "Do you have field index policies configured for faster log queries?"
        ):
            if check.result:
                total_groups = check.result.get("total_log_groups", 0)
                indexed_groups = check.result.get("indexed_log_groups", 0)
                sample_groups = check.result.get("sample_indexed_groups", [])
                field_details = check.result.get("field_index_details", [])

                if indexed_groups > 0:
                    sample_info = (
                        f"Examples: {', '.join(sample_groups[:3])}"
                        if sample_groups
                        else ""
                    )

                    # Add field index details
                    if field_details:
                        details_html = ""
                        for detail in field_details[
                            :3
                        ]:  # Show first 3 with field names
                            log_group = detail.get("log_group", "Unknown")
                            field_names = detail.get("field_names", [])
                            details_html += f"<strong>{log_group}</strong><br>Fields: {', '.join(field_names[:5])}<br><br>"

                        return f"Found {indexed_groups}/{total_groups} log groups with field indexes (top 20 largest by size) | {sample_info}<details><summary>Show Field Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details_html}</div></details>"

                    return f"Found {indexed_groups}/{total_groups} log groups with field indexes (top 20 largest by size) | {sample_info}"
                return f"Checked {plural(total_groups, 'log group')} (top 20 largest by size) - {indexed_groups}/{total_groups} have field indexes"
            return "No log groups checked for field indexes"

        elif (
            check.name
            == "What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?"
        ):
            if isinstance(check.result, list):
                # Count instances with detailed monitoring enabled
                enabled_instances = []
                for reservation in check.result:
                    if isinstance(reservation, list):
                        enabled_instances.extend(reservation)

                if enabled_instances:
                    summary = f"Found {len(enabled_instances)} EC2 instances with detailed monitoring enabled"

                    # Create detailed breakdown
                    details = f"<strong>Instances with Detailed Monitoring ({len(enabled_instances)}):</strong><br>"
                    for i, instance in enumerate(enabled_instances, 1):
                        instance_id = instance.get("InstanceId", "Unknown")
                        instance_type = instance.get("InstanceType", "Unknown")
                        state = instance.get("State", {}).get("Name", "Unknown")
                        monitoring = instance.get("Monitoring", {}).get(
                            "State", "Unknown"
                        )

                        details += f"{i}. <strong>{instance_id}</strong><br>"
                        details += f"   Type: {instance_type}<br>"
                        details += f"   State: {state}<br>"
                        details += f"   Monitoring: {monitoring}<br><br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    return "No EC2 instances have detailed monitoring enabled - all instances are using basic (5-minute) monitoring"
            return "EC2 detailed monitoring check completed"

        elif check.name == "How many ECS clusters are available to monitor?":
            cluster_arns = check.result.get("clusterArns", [])
            if cluster_arns:
                cluster_names = [arn.split("/")[-1] for arn in cluster_arns]
                summary = f"Found {plural(len(cluster_arns), 'ECS cluster')}"
                details = "<br>".join(cluster_names[:10])
                if len(cluster_names) > 10:
                    details += (
                        f"<br>... and {plural(len(cluster_names) - 10, 'more cluster')}"
                    )
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No ECS clusters found"

        elif check.name == "Do you have ECS clusters with Container Insights enabled?":
            clusters = check.result.get("clusters", [])
            if clusters:
                insights_enabled = []
                insights_disabled = []

                for cluster in clusters:
                    cluster_name = cluster.get("clusterName", "Unknown")
                    cluster_arn = cluster.get("clusterArn", "Unknown")
                    status = cluster.get("status", "Unknown")
                    settings = cluster.get("settings", [])

                    insights_value = "disabled"  # default
                    for setting in settings:
                        if setting.get("name") == "containerInsights":
                            insights_value = setting.get("value", "disabled")
                            break

                    cluster_info = {
                        "name": cluster_name,
                        "arn": cluster_arn,
                        "status": status,
                        "insights": insights_value,
                    }

                    if insights_value in ["enabled", "enhanced"]:
                        insights_enabled.append(cluster_info)
                    else:
                        insights_disabled.append(cluster_info)

                summary = f"Found {plural(len(clusters), 'ECS cluster')} | Container Insights: {len(insights_enabled)} enabled, {len(insights_disabled)} disabled"

                # Create detailed breakdown
                details = ""
                if insights_enabled:
                    details += f"<strong>Clusters with Container Insights Enabled ({len(insights_enabled)}):</strong><br>"
                    for i, cluster in enumerate(insights_enabled, 1):
                        details += f"{i}. <strong>{cluster['name']}</strong><br>"
                        details += f"   Status: {cluster['status']}<br>"
                        details += f"   Container Insights: {cluster['insights']}<br>"
                        details += f"   ARN: {cluster['arn']}<br><br>"

                if insights_disabled:
                    details += f"<strong>Clusters with Container Insights Disabled ({len(insights_disabled)}):</strong><br>"
                    for i, cluster in enumerate(insights_disabled, 1):
                        details += f"{i}. <strong>{cluster['name']}</strong><br>"
                        details += f"   Status: {cluster['status']}<br>"
                        details += f"   Container Insights: {cluster['insights']}<br>"
                        details += f"   ARN: {cluster['arn']}<br><br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No ECS clusters found"

        elif (
            check.name
            == "Do you have EKS clusters with the CloudWatch Observability add-on enabled?"
        ):
            if check.result:
                total_clusters = check.result.get("total_clusters", 0)
                observability_clusters = check.result.get("observability_clusters", 0)
                clusters_with_obs = check.result.get("clusters_with_observability", [])
                cluster_details = check.result.get("cluster_addon_details", [])

                summary = f"Found {observability_clusters}/{total_clusters} EKS clusters with the CloudWatch Observability add-on"

                if observability_clusters > 0:
                    # Create detailed breakdown
                    details = f"<strong>EKS Clusters with CloudWatch Observability Add-on ({observability_clusters}):</strong><br>"

                    if cluster_details:
                        for i, detail in enumerate(cluster_details, 1):
                            cluster_name = detail.get("cluster_name", "Unknown")
                            addon_version = detail.get("addon_version", "Unknown")
                            addon_status = detail.get("addon_status", "Unknown")

                            details += f"{i}. <strong>{cluster_name}</strong><br>"
                            details += f"   Add-on Version: {addon_version}<br>"
                            details += f"   Status: {addon_status}<br><br>"
                    else:
                        # Fallback to cluster names
                        for i, cluster in enumerate(clusters_with_obs, 1):
                            details += f"{i}. {cluster}<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"

                return f"Checked {plural(total_clusters, 'EKS cluster')} - {observability_clusters}/{total_clusters} have the CloudWatch Observability add-on"
            return "No EKS clusters checked for add-ons"

        # Handle different AWS service responses with expandable details
        if (
            check.name
            == "Do you have standardized Logs Insights queries for common troubleshooting scenarios (errors, latency, security events)?"
        ):
            query_definitions = check.result.get("queryDefinitions", [])
            if query_definitions:
                summary = (
                    f"Found {plural(len(query_definitions), 'saved query definition')}"
                )
                details = ""
                for i, query_def in enumerate(query_definitions[:10], 1):
                    name = query_def.get("name", "Unnamed")
                    query_string = query_def.get("queryString", "No query string")[:150]
                    log_groups = query_def.get("logGroupNames", [])
                    log_group_info = (
                        f"Groups: {', '.join(log_groups[:3])}"
                        if log_groups
                        else "No log groups"
                    )
                    details += f"<strong>{i}. {name}</strong><br>Query: {query_string}<br>{log_group_info}<br><br>"
                if len(query_definitions) > 10:
                    details += f"... and {plural(len(query_definitions) - 10, 'more query', 'more queries')}"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No saved query definitions found - users haven't saved any custom CloudWatch Logs Insights queries for reuse"

        elif (
            check.name == "Do you have CloudWatch alarms configured for your resources?"
        ):
            metric_alarms = check.result.get("MetricAlarms", [])
            composite_alarms = check.result.get("CompositeAlarms", [])
            total_alarms = len(metric_alarms) + len(composite_alarms)
            if total_alarms > 0:
                summary = f"Found {plural(total_alarms, 'alarm')} ({len(metric_alarms)} metric, {len(composite_alarms)} composite)"
                details = "<strong>Metric Alarms:</strong><br>" + "<br>".join(
                    [alarm.get("AlarmName", "Unknown") for alarm in metric_alarms[:10]]
                )
                if len(metric_alarms) > 10:
                    details += f"<br>... and {plural(len(metric_alarms) - 10, 'more metric alarm')}"
                if composite_alarms:
                    details += (
                        "<br><br><strong>Composite Alarms:</strong><br>"
                        + "<br>".join(
                            [
                                alarm.get("AlarmName", "Unknown")
                                for alarm in composite_alarms[:10]
                            ]
                        )
                    )
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No alarms found"

        elif (
            check.name
            == "Do you have CloudWatch dashboards for visualizing metrics and logs?"
        ):
            dashboards = check.result.get("DashboardEntries", [])
            if dashboards:
                summary = f"Found {plural(len(dashboards), 'dashboard')}"
                details = "<br>".join(
                    [dash.get("DashboardName", "Unknown") for dash in dashboards[:15]]
                )
                if len(dashboards) > 15:
                    details += (
                        f"<br>... and {plural(len(dashboards) - 15, 'more dashboard')}"
                    )
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No dashboards found"

        elif check.name == "Do your alarms send notifications to SNS topics?":
            if check.result:
                total_checked = check.result.get("total_alarms_checked", 0)
                alarms_with_sns = check.result.get("alarms_with_sns", 0)
                alarms_without_sns = check.result.get("alarms_without_sns", 0)
                alarms_with_sns_details = check.result.get(
                    "alarms_with_sns_details", []
                )
                alarms_without_sns_details = check.result.get(
                    "alarms_without_sns_details", []
                )

                summary = f"SNS configured for {alarms_with_sns} of {total_checked} alarms checked"

                # Create detailed breakdown
                details = f"<strong>Alarms with SNS Configuration ({alarms_with_sns}):</strong><br>"
                for i, alarm in enumerate(alarms_with_sns_details, 1):
                    alarm_name = alarm.get("AlarmName", "Unknown")
                    sns_topics = alarm.get("SNSTopics", [])
                    details += f"{i}. <strong>{alarm_name}</strong><br>"
                    details += f"   SNS Topics: {len(sns_topics)}<br>"
                    for j, topic in enumerate(sns_topics[:2], 1):
                        topic_name = topic.split(":")[-1] if ":" in topic else topic
                        details += f"     {j}. {topic_name}<br>"
                    if len(sns_topics) > 2:
                        details += f"     ... and {plural(len(sns_topics) - 2, 'more topic')}<br>"
                    details += "<br>"

                if alarms_without_sns > 0:
                    details += f"<br><strong>Alarms without SNS Configuration ({alarms_without_sns}):</strong><br>"
                    for i, alarm in enumerate(alarms_without_sns_details[:10], 1):
                        alarm_name = alarm.get("AlarmName", "Unknown")
                        details += f"{i}. {alarm_name}<br>"
                    if len(alarms_without_sns_details) > 10:
                        details += f"... and {plural(len(alarms_without_sns_details) - 10, 'more alarm')} without SNS<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No alarms found to check"

        elif check.name == "Do you use anomaly detection models for adaptive alarming?":
            if check.result:
                total_bands = check.result.get("total_bands", 0)
                bands_details = check.result.get("bands_details", [])

                if total_bands > 0:
                    summary = f"Found {plural(total_bands, 'anomaly detection band')} configured"

                    # Create detailed breakdown
                    details = (
                        f"<strong>Anomaly Detection Bands ({total_bands}):</strong><br>"
                    )
                    for i, band in enumerate(bands_details, 1):
                        namespace = band.get("Namespace", "Unknown")
                        metric_name = band.get("MetricName", "Unknown")
                        dimensions = band.get("Dimensions", "None")
                        state = band.get("State", "Unknown")

                        details += (
                            f"{i}. <strong>{namespace}/{metric_name}</strong><br>"
                        )
                        details += f"   State: {state}<br>"
                        if dimensions and dimensions != "None":
                            details += f"   Dimensions: {dimensions}<br>"
                        details += "<br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    return "No anomaly detection bands configured"
            return "No anomaly detection bands found"

        elif (
            check.name
            == "Do your log groups have resource tags for retention governance and metadata-based search?"
        ):
            tagged = check.result.get("tagged_log_groups", []) if check.result else []
            if tagged:
                summary = f"Found {plural(len(tagged), 'tagged log group')}"
                details = ""
                for i, lg in enumerate(tagged[:15], 1):
                    tag_str = ", ".join(f"{k}={v}" for k, v in lg["tags"].items())
                    details += f"{i}. <strong>{lg['name']}</strong><br>   Tags: {tag_str}<br><br>"
                if len(tagged) > 15:
                    details += (
                        f"... and {plural(len(tagged) - 15, 'more tagged log group')}"
                    )
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No tagged log groups found"

        elif (
            check.name
            == "Do you have stale or unused log groups that are collecting data but not being used?"
        ):
            total = check.result.get("total_checked", 0) if check.result else 0
            stale = check.result.get("stale_log_groups", 0) if check.result else 0
            active = check.result.get("active_log_groups", 0) if check.result else 0
            pct = check.result.get("stale_percentage", 0) if check.result else 0
            stale_list = check.result.get("stale_details", []) if check.result else []
            if total == 0:
                return "No log groups checked"
            summary = f"Checked the {plural(total, 'largest log group')}: {active} active, {stale} stale/unused ({pct}%)"
            if stale_list:
                details = ""
                for i, s in enumerate(stale_list[:20], 1):
                    days = s.get("days_since_ingestion", -1)
                    reason = (
                        f"{plural(days, 'day')} since last ingestion"
                        if days > 0
                        else s.get("reason", "unknown")
                    )
                    details += f"{i}. <strong>{s['name']}</strong> — {reason}<br>"
                if len(stale_list) > 20:
                    details += f"... and {len(stale_list) - 20} more"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return summary

        elif (
            check.name
            == "Do you use resource tags for organizing and managing AWS resources?"
        ):
            resources = (
                check.result.get("ResourceTagMappingList", []) if check.result else []
            )
            if resources:
                summary = f"Found {plural(len(resources), 'tagged resource')}"
                details = ""
                for i, resource in enumerate(resources[:15], 1):
                    resource_arn = resource.get("ResourceARN", "Unknown")
                    resource_type = (
                        resource_arn.split(":")[2] if ":" in resource_arn else "Unknown"
                    )
                    resource_name = (
                        resource_arn.split("/")[-1]
                        if "/" in resource_arn
                        else resource_arn.split(":")[-1]
                    )
                    tags = resource.get("Tags", [])
                    tag_count = len(tags)
                    details += f"{i}. <strong>{resource_type}</strong>: {resource_name}<br>   Tags: {tag_count}<br><br>"
                if len(resources) > 15:
                    details += (
                        f"... and {plural(len(resources) - 15, 'more tagged resource')}"
                    )
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No tagged resources found"

        elif (
            check.name
            == "Do you use CloudWatch Synthetics to monitor application endpoints?"
        ):
            canaries = check.result.get("Canaries", []) if check.result else []
            if canaries:
                summary = f"Found {plural(len(canaries), 'synthetic canary', 'synthetic canaries')}"
                details = ""
                for i, canary in enumerate(canaries, 1):
                    name = canary.get("Name", "Unknown")
                    status = canary.get("Status", {}).get("State", "Unknown")
                    runtime_version = canary.get("RuntimeVersion", "Unknown")
                    details += f"{i}. <strong>{name}</strong><br>   Status: {status}<br>   Runtime: {runtime_version}<br><br>"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No synthetic canaries found"

        elif (
            check.name == "Do you use CloudWatch RUM to monitor real user experiences?"
        ):
            apps = check.result.get("AppMonitorSummaries", []) if check.result else []
            if apps:
                summary = f"Found {plural(len(apps), 'RUM application')}"
                details = ""
                for i, app in enumerate(apps, 1):
                    name = app.get("Name", "Unknown")
                    domain = app.get("Domain", "Unknown")
                    state = app.get("State", "Unknown")
                    details += f"{i}. <strong>{name}</strong><br>   Domain: {domain}<br>   State: {state}<br><br>"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No RUM applications found"

        elif (
            check.name
            == "Do you have any Systems Manager OpsCenter actions configured with your alarms?"
        ):
            if check.result:
                total_checked = check.result.get("total_alarms_checked", 0)
                alarms_with_opsitem = check.result.get("alarms_with_opsitem", 0)
                alarms_without_opsitem = check.result.get("alarms_without_opsitem", 0)
                alarms_with_opsitem_details = check.result.get(
                    "alarms_with_opsitem_details", []
                )
                alarms_without_opsitem_details = check.result.get(
                    "alarms_without_opsitem_details", []
                )

                summary = f"OpsItem actions configured for {alarms_with_opsitem} of {total_checked} alarms checked"

                # Create detailed breakdown
                details = f"<strong>Alarms with OpsItem Actions ({alarms_with_opsitem}):</strong><br>"
                for i, alarm in enumerate(alarms_with_opsitem_details, 1):
                    alarm_name = alarm.get("AlarmName", "Unknown")
                    opsitem_actions = alarm.get("OpsItemActions", [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += f"   <strong>OpsItem Actions ({len(opsitem_actions)}):</strong><br>"
                    for j, action in enumerate(opsitem_actions, 1):
                        details += f"     {j}. ARN: {action}<br>"
                    details += "<br>"

                if alarms_without_opsitem > 0:
                    details += f"<br><strong>Alarms without OpsItem Actions ({alarms_without_opsitem}):</strong><br>"
                    for i, alarm in enumerate(alarms_without_opsitem_details[:10], 1):
                        alarm_name = alarm.get("AlarmName", "Unknown")
                        details += f"{i}. {alarm_name}<br>"
                    if len(alarms_without_opsitem_details) > 10:
                        details += f"... and {plural(len(alarms_without_opsitem_details) - 10, 'more alarm')} without OpsItem actions<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No alarms found to check"

        elif (
            check.name
            == "Do you use CloudWatch Application Signals to monitor application services?"
        ):
            services = check.result.get("Services", []) if check.result else []
            if services:
                summary = (
                    f"Found {plural(len(services), 'Application Signals service')}"
                )
                details = ""
                for i, service in enumerate(services[:10], 1):
                    key_attrs = service.get("KeyAttributes", {})
                    service_name = key_attrs.get("Name", "Unknown")
                    environment = key_attrs.get("Environment", "Unknown")
                    svc_type = key_attrs.get("Type", "Unknown")
                    # Get platform from AttributeMaps
                    platform = "Unknown"
                    for attr_map in service.get("AttributeMaps", []):
                        if "PlatformType" in attr_map:
                            platform = attr_map["PlatformType"]
                            break
                    details += f"{i}. <strong>{service_name}</strong><br>   Environment: {environment} | Platform: {platform} | Type: {svc_type}<br><br>"
                if len(services) > 10:
                    details += f"... and {plural(len(services) - 10, 'more service')}"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No Application Signals services found"

        elif (
            check.name
            == "Have you defined Service Level Objectives (SLOs) for critical application services?"
        ):
            slos = check.result.get("SloSummaries", []) if check.result else []
            if slos:
                summary = f"Found {plural(len(slos), 'Application Signals SLO')}"
                details = ""
                for i, slo in enumerate(slos, 1):
                    name = slo.get("Name", "Unknown")
                    service_name = slo.get("ServiceName", "Unknown")
                    details += f"{i}. <strong>{name}</strong><br>   Service: {service_name}<br><br>"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No Application Signals SLOs found"

        elif (
            check.name == "Do you use AWS DevOps Agent for AI-assisted troubleshooting?"
        ):
            if check.result:
                total_spaces = check.result.get("total_spaces", 0)
                spaces_details = check.result.get("spaces_details", [])
                regions_checked = check.result.get("regions_checked", [])

                if total_spaces > 0:
                    summary = f"Found {plural(total_spaces, 'AWS DevOps Agent space')}"

                    # Create detailed breakdown
                    details = f"<strong>AWS DevOps Agent Spaces ({total_spaces}):</strong><br>"
                    details += f"<em>Regions checked: {', '.join(regions_checked)}</em><br><br>"

                    for i, space in enumerate(spaces_details, 1):
                        name = space.get("name", "Unknown")
                        space_id = space.get("agentSpaceId", "Unknown")
                        created_at = space.get("createdAt", "Unknown")
                        updated_at = space.get("updatedAt", "Unknown")
                        region = space.get("region", "Unknown")

                        details += f"{i}. <strong>{name}</strong> ({region})<br>"
                        details += f"   ID: {space_id}<br>"
                        details += f"   Created: {created_at}<br>"
                        details += f"   Updated: {updated_at}<br><br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    regions_str = (
                        ", ".join(regions_checked) if regions_checked else "none"
                    )
                    return f"No AWS DevOps Agent spaces found (checked regions: {regions_str})"
            return "AWS DevOps Agent service not accessible"

        elif (
            check.name
            == "Do you use CloudWatch Omni spaces for unified access to logs, metrics, and traces?"
        ):
            result = check.result or {}
            total_spaces = result.get("total_spaces", 0)
            active_spaces = result.get("active_spaces", 0)
            region = result.get("region", self.region)
            if total_spaces == 0:
                return f"No CloudWatch Omni spaces found in {region}"

            scope = (
                "organization domain"
                if result.get("has_organization_domain")
                else "account domain"
            )
            summary = f"Found {active_spaces} active of {total_spaces} CloudWatch Omni spaces in {region} ({scope})"
            details = "<strong>CloudWatch Omni Domains:</strong><br>"
            if not result.get("domains_listed", True):
                details += "<em>Domains could not be listed</em><br>"
            for domain in result.get("domains_details", []):
                identity = (
                    "IAM Identity Center" if domain.get("identityCenter") else "IAM"
                )
                details += f"• <strong>{esc(domain.get('name'))}</strong> — {esc(domain.get('scope'))} scope, {identity} sign-in, {esc(domain.get('status'))}<br>"
            details += (
                f"<br><strong>CloudWatch Omni Spaces ({total_spaces}):</strong><br>"
            )
            for i, space in enumerate(result.get("spaces_details", []), 1):
                details += f"{i}. <strong>{esc(space.get('name'))}</strong> — {esc(space.get('status'))}<br>"
                details += f"   ID: {esc(space.get('spaceId'))}<br>"
                details += f"   Domain scope: {esc(space.get('scope'))}<br>"
                details += f"   Created: {esc(space.get('createdAt'))}<br><br>"
            return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"

        elif (
            check.name
            == "Have you connected CloudWatch Omni integrations (Context Graph resource discovery, Slack, external agents)?"
        ):
            result = check.result or {}
            total = result.get("total_integrations", 0)
            active = result.get("active_integrations", 0)
            region = result.get("region", self.region)
            if total == 0:
                return f"No CloudWatch Omni integrations found in {region}"

            by_type = ", ".join(
                f"{esc(name)}: {count}"
                for name, count in sorted(result.get("active_by_type", {}).items())
            )
            summary = f"Found {active} active of {total} CloudWatch Omni integrations in {region}"
            if by_type:
                summary += f" ({by_type})"
            details = f"<strong>CloudWatch Omni Integrations ({total}):</strong><br>"
            for i, integration in enumerate(result.get("integrations_details", []), 1):
                details += f"{i}. <strong>{esc(integration.get('name'))}</strong> — {esc(integration.get('type'))}, {esc(integration.get('status'))}, {esc(integration.get('scope'))} scope<br>"
            return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"

        elif (
            check.name == "Do you have any Lambda actions configured with your alarms?"
        ):
            if check.result:
                total_checked = check.result.get("total_alarms_checked", 0)
                alarms_with_lambda = check.result.get("alarms_with_lambda", 0)
                check.result.get("alarms_without_lambda", 0)
                alarms_with_lambda_details = check.result.get(
                    "alarms_with_lambda_details", []
                )
                check.result.get("alarms_without_lambda_details", [])

                summary = f"Lambda actions configured for {alarms_with_lambda} of {total_checked} alarms checked"

                # Create detailed breakdown - only show alarms with Lambda actions
                details = f"<strong>Alarms with Lambda Actions ({alarms_with_lambda}):</strong><br>"
                for i, alarm in enumerate(alarms_with_lambda_details, 1):
                    alarm_name = alarm.get("AlarmName", "Unknown")
                    lambda_actions = alarm.get("LambdaActions", [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += f"   <strong>Lambda Actions ({len(lambda_actions)}):</strong><br>"
                    for j, action in enumerate(lambda_actions, 1):
                        function_name = (
                            action.split(":")[-1] if ":" in action else action
                        )
                        details += f"     {j}. Function: {function_name}<br>"
                        details += f"        ARN: {action}<br>"
                    details += "<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No alarms found to check"

        elif (
            check.name
            == "Have you configured CloudWatch Investigations actions for any alarms?"
        ):
            if check.result:
                total_checked = check.result.get("total_alarms_checked", 0)
                alarms_with_investigations = check.result.get(
                    "alarms_with_investigations", 0
                )
                check.result.get("alarms_without_investigations", 0)
                alarms_with_investigations_details = check.result.get(
                    "alarms_with_investigations_details", []
                )
                check.result.get("alarms_without_investigations_details", [])

                summary = f"CloudWatch Investigations actions configured for {alarms_with_investigations} of {total_checked} alarms checked"

                # Create detailed breakdown
                details = f"<strong>Alarms with CloudWatch Investigations Actions ({alarms_with_investigations}):</strong><br>"
                for i, alarm in enumerate(alarms_with_investigations_details, 1):
                    alarm_name = alarm.get("AlarmName", "Unknown")
                    investigations_actions = alarm.get("InvestigationsActions", [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += f"   <strong>Investigations Actions ({len(investigations_actions)}):</strong><br>"
                    for j, action in enumerate(investigations_actions, 1):
                        details += f"     {j}. ARN: {action}<br>"
                    details += "<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No alarms found to check"

        elif check.name == "Do you have any EC2 actions configured with your alarms?":
            if check.result:
                total_checked = check.result.get("total_alarms_checked", 0)
                alarms_with_ec2 = check.result.get("alarms_with_ec2", 0)
                alarms_with_ec2_details = check.result.get(
                    "alarms_with_ec2_details", []
                )

                summary = f"EC2 actions configured for {alarms_with_ec2} of {total_checked} alarms checked"

                # Create detailed breakdown - only show alarms with EC2 actions
                details = (
                    f"<strong>Alarms with EC2 Actions ({alarms_with_ec2}):</strong><br>"
                )
                for i, alarm in enumerate(alarms_with_ec2_details, 1):
                    alarm_name = alarm.get("AlarmName", "Unknown")
                    ec2_actions = alarm.get("EC2Actions", [])
                    details += f"{i}. <strong>Alarm:</strong> {alarm_name}<br>"
                    details += (
                        f"   <strong>EC2 Actions ({len(ec2_actions)}):</strong><br>"
                    )
                    for j, action in enumerate(ec2_actions, 1):
                        details += f"     {j}. ARN: {action}<br>"
                    details += "<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return "No alarms found to check"

        elif (
            check.name
            == "What percentage of the largest log groups have retention policies configured (example thresholds: security: 90+ days, operational: 30 days, debug: 7 days — actual requirements vary by organization)?"
        ):
            if check.result:
                top_groups = check.result.get("top_log_groups", [])
                groups_with_retention = check.result.get("groups_with_retention", 0)
                total_size_gb = check.result.get("total_size_gb", 0)

                if top_groups:
                    summary = f"Analyzed the {plural(len(top_groups), 'largest log group')} ({total_size_gb:.1f} GB total) | {groups_with_retention}/{len(top_groups)} have retention policies"

                    # Create detailed breakdown
                    details = ""
                    for i, group in enumerate(top_groups, 1):
                        name = group.get("name", "Unknown")
                        size_mb = group.get("size_mb", 0)
                        retention = group.get("retention_days")
                        retention_str = (
                            "Never expire"
                            if retention is None
                            else plural(retention, "day")
                        )
                        details += f"{i}. {name}<br>   Size: {size_mb:.1f} MB | Retention: {retention_str}<br><br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return f"{base_info} | No large log groups found for retention analysis"
            return f"{base_info} - No retention analysis performed"

        elif (
            check.name
            == "Do you have X-Ray groups configured for focused trace analysis?"
        ):
            groups = check.result.get("Groups", []) if check.result else []
            # Filter out the Default group
            custom_groups = [g for g in groups if g.get("GroupName") != "Default"]

            if custom_groups:
                summary = f"Found {plural(len(custom_groups), 'custom X-Ray group')}"
                details = ""
                for i, group in enumerate(custom_groups, 1):
                    name = group.get("GroupName", "Unknown")
                    filter_expr = group.get("FilterExpression", "No filter")
                    insights = group.get("InsightsConfiguration", {})
                    insights_enabled = insights.get("InsightsEnabled", False)

                    details += f"{i}. <strong>{name}</strong><br>"
                    details += f"   Filter: {filter_expr}<br>"
                    details += f"   Insights: {'Enabled' if insights_enabled else 'Disabled'}<br><br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            else:
                return "No custom X-Ray groups configured (only Default group exists)"

        elif check.name == "Do you have custom X-Ray sampling rules configured?":
            sampling_rules = (
                check.result.get("SamplingRuleRecords", []) if check.result else []
            )
            custom_rules = [
                rule
                for rule in sampling_rules
                if rule.get("SamplingRule", {}).get("RuleName") != "Default"
            ]

            if custom_rules:
                summary = f"Found {plural(len(custom_rules), 'custom sampling rule')}"
                details = ""
                for i, record in enumerate(custom_rules, 1):
                    rule = record.get("SamplingRule", {})
                    name = rule.get("RuleName", "Unknown")
                    priority = rule.get("Priority", "Unknown")
                    fixed_rate = rule.get("FixedRate", 0)
                    service = rule.get("ServiceName", "*")
                    details += f"{i}. <strong>{name}</strong><br>"
                    details += f"   Priority: {priority}<br>"
                    details += f"   Fixed Rate: {fixed_rate * 100}%<br>"
                    details += f"   Service: {service}<br><br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            else:
                default_count = len(sampling_rules)
                if default_count == 0:
                    default_info = "no default rules exist"
                elif default_count == 1:
                    default_info = "only 1 default rule exists"
                else:
                    default_info = f"only {default_count} default rules exist"
                return f"No custom sampling rules configured ({default_info})"

        elif (
            check.name
            == "Do your traces contain custom annotations indicating manual instrumentation?"
        ):
            total = check.result.get("total_traces", 0) if check.result else 0
            custom_count = (
                check.result.get("traces_with_custom_annotations", 0)
                if check.result
                else 0
            )
            keys = (
                check.result.get("custom_annotation_keys", []) if check.result else []
            )
            if custom_count > 0:
                summary = f"Found {custom_count}/{total} traces with custom annotations"
                details = f"Custom annotation keys: {', '.join(keys)}"
                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            return f"No custom annotations found in {plural(total, 'sampled trace')}"

        elif (
            check.name == "Do you have X-Ray Insights configured for anomaly detection?"
        ):
            if check.result:
                groups = check.result.get("insights_enabled_groups", 0)
                notif = check.result.get("notifications_enabled_groups", 0)
                names = check.result.get("group_names", [])
                recent = check.result.get("recent_insights", 0)
                if groups > 0:
                    summary = f"{plural(groups, 'X-Ray group')} with Insights enabled ({notif} with notifications)"
                    details = (
                        f"Groups: {', '.join(names)}<br>Recent insights (24h): {recent}"
                    )
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                return "No X-Ray groups have Insights enabled"
            return "Could not check X-Ray Insights configuration"

        elif (
            check.name
            == "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)?"
        ):
            if isinstance(check.result, dict):
                total = check.result.get("total_log_groups", 0)
                vended_count = check.result.get("vended_count", 0)
                custom_count = check.result.get("custom_count", 0)
                vended_logs = check.result.get("vended_logs", [])
                custom_logs = check.result.get("custom_logs", [])

                summary = f"Total: {plural(total, 'log group')} | Vended: {vended_count} | Custom: {custom_count}"
                details = ""

                if vended_logs:
                    details += "<strong>AWS Vended/Service Logs:</strong><br>"
                    for log in vended_logs:
                        details += f"  • {log}<br>"
                    details += "<br>"

                if custom_logs:
                    details += "<strong>Custom Application Logs:</strong><br>"
                    for log in custom_logs:
                        details += f"  • {log}<br>"

                return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
            else:
                return "No log groups found"

        elif (
            check.name
            == "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?"
        ):
            if isinstance(check.result, dict):
                clusters = check.result.get("clusters", [])
                enabled_types = check.result.get("enabled_types", 0)
                if clusters:
                    cluster_summary = ", ".join(
                        [
                            f"{c['cluster']} ({len(c['enabled_types'])}/5)"
                            for c in clusters[:3]
                        ]
                    )
                    all_enabled = check.result.get("clusters_all_enabled", 0)
                    return f"Found {plural(len(clusters), 'EKS cluster')} | {all_enabled}/{len(clusters)} with all 5 log types enabled | {enabled_types}/5 log types enabled on at least one cluster (e.g., {cluster_summary})"
                return "No EKS clusters found"
            return "No EKS control plane log configuration found"

        elif check.name == "Do you have dashboards configured with variables?":
            if check.result:
                total_dashboards = check.result.get("total_dashboards", 0)
                dashboards_with_variables = check.result.get(
                    "dashboards_with_variables", 0
                )
                dashboards_with_variables_details = check.result.get(
                    "dashboards_with_variables_details", []
                )

                if dashboards_with_variables > 0:
                    summary = f"{base_info} | {dashboards_with_variables}/{total_dashboards} dashboards have dynamic variables"

                    # Create detailed breakdown
                    details = f"<strong>Dashboards with Variables ({dashboards_with_variables}):</strong><br>"
                    for i, dashboard in enumerate(dashboards_with_variables_details, 1):
                        name = dashboard.get("DashboardName", "Unknown")
                        indicators = dashboard.get("VariableIndicators", [])
                        size = dashboard.get("Size", 0)
                        details += f"{i}. <strong>{name}</strong><br>"
                        details += f"   Variable Features: {', '.join(indicators)}<br>"
                        details += f"   Size: {plural(size, 'byte')}<br><br>"

                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"

                return f"{base_info} | {dashboards_with_variables}/{total_dashboards} dashboards have dynamic variables"
            return f"{base_info} | No dashboards found"

        elif (
            check.name
            == "Do you have a history of Logs Insights queries being executed?"
        ):
            command_info = f"Command: {check.command}"
            queries = check.result.get("queries", [])
            if queries:
                # Filter out system/default queries (Application Signals, etc.)
                custom_queries = [
                    query
                    for query in queries
                    if not any(
                        pattern in query.get("queryString", "")
                        for pattern in [
                            'SOURCE "/aws/application-signals/',
                            "/aws/containerinsights/",  # Container Insights auto queries
                        ]
                    )
                ]

                if custom_queries:
                    query_details = []
                    for query in custom_queries[:3]:  # Show first 3 custom queries
                        query_id = esc(query.get("queryId", "Unknown")[:8])
                        query_string = esc(
                            query.get("queryString", "No query string")[:80]
                        )
                        status = esc(query.get("status", "Unknown"))
                        query_details.append(
                            f"ID:{query_id} Status:{status} Query:{query_string}"
                        )

                    return f"{command_info} | Found {plural(len(custom_queries), 'custom query', 'custom queries')} (filtered from {len(queries)} total) | Details: {' | '.join(query_details)}"
                return f"{command_info} | Found {plural(len(queries), 'total query', 'total queries')} but no custom user-generated queries (all appear to be system/auto-generated)"
            return f"{command_info} | No query history found - no CloudWatch Logs Insights queries have been executed recently"

        elif (
            check.name
            == "What percentage of application logs use structured JSON format for easier parsing and analysis?"
        ):
            total_checked = check.result.get("total_groups_checked", 0)
            json_groups = check.result.get("json_groups", 0)
            sample_groups = check.result.get("sample_groups", [])

            summary = f"Analyzed the {plural(total_checked, 'largest log group')} | {json_groups}/{total_checked} have JSON structured logs"
            if json_groups > 0 and sample_groups:
                return f"{summary} | Examples: {', '.join(esc(g) for g in sample_groups[:3])}"
            return summary

        elif (
            check.name
            == "Do you use X-Ray service maps to visualize application architecture?"
        ):
            services = check.result.get("Services", [])
            if services:
                sample_names = [esc(svc.get("Name", "Unknown")) for svc in services[:3]]
                return f"{base_info} | Found {plural(len(services), 'X-Ray service')} (e.g., {', '.join(sample_names)})"
            return f"{base_info} | No X-Ray services found"

        # Default handler for other checks
        else:
            # Try to find common patterns in the result
            if isinstance(check.result, dict):
                # Count items in common AWS response patterns
                item_count = 0
                items = []

                # Common AWS response patterns
                for key in [
                    "Items",
                    "Resources",
                    "Clusters",
                    "Services",
                    "Policies",
                    "Rules",
                    "Metrics",
                ]:
                    if key in check.result:
                        items = check.result[key]
                        item_count = len(items)
                        break

                if item_count > 0:
                    summary = f"Found {plural(item_count, 'item')}"
                    # Try to extract names or IDs
                    details = ""
                    for i, item in enumerate(items[:15]):
                        if isinstance(item, dict):
                            # Look for common name fields
                            name = (
                                item.get("Name")
                                or item.get("name")
                                or item.get("Id")
                                or item.get("id")
                                or str(item)[:100]
                            )
                            details += f"{name}<br>"
                        else:
                            details += f"{str(item)[:100]}<br>"
                    if len(items) > 15:
                        details += f"... and {plural(len(items) - 15, 'more item')}"
                    return f"{summary}<details><summary>Show Details</summary><div style='white-space: pre-wrap; word-wrap: break-word; max-width: 100%;'>{details}</div></details>"
                else:
                    return "No items found"
            else:
                return "Command executed successfully"
