# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0


class MetricsDiscoveryMixin:
    """Collect custom metric and Application Signals data."""

    def execute_custom_metrics_namespaces_check(self):
        """Custom check for truly custom application metrics (excluding AWS-generated and CWAgent system metrics)"""
        try:
            # Get all metrics and filter for custom namespaces
            metrics_result = self.run_aws_command(
                "aws cloudwatch list-metrics --output json"
            )
            if metrics_result is None:
                return None
            if "Metrics" not in metrics_result:
                return {"custom_namespaces": [], "total_custom_metrics": 0}

            all_metrics = metrics_result["Metrics"]
            custom_metrics = []
            custom_namespaces = set()

            # AWS-generated namespaces to exclude (not truly custom)
            aws_generated_namespaces = {
                # Observability services
                "CloudWatchSynthetics",
                "LambdaInsights",
                "ContainerInsights",
                "ECS/ContainerInsights",
                "ApplicationSignals",
                "AWS/X-Ray",
                # Container/Kubernetes
                "kubernetes.io",
                "ContainerInsights/Prometheus",
                "EKS/ContainerInsights",
                # Application monitoring
                "AWS/ApplicationInsights",
                "AWS/Usage",
                # Custom patterns that are AWS-generated
                "AWS/Events",
                "AWS/Logs/LogDelivery",
                "System/Linux",
                "System/Windows",
                # Third-party integrations managed by AWS
                "Prometheus",
                "Grafana",
                "Datadog",
                "NewRelic",
            }

            # CWAgent system metric names (not custom application metrics)
            cwagent_system_metrics = {
                "cpu_usage_idle",
                "cpu_usage_iowait",
                "cpu_usage_system",
                "cpu_usage_user",
                "cpu_usage_nice",
                "cpu_usage_steal",
                "cpu_usage_guest",
                "disk_used_percent",
                "disk_inodes_free",
                "disk_inodes_used",
                "disk_free",
                "disk_used",
                "disk_total",
                "diskio_reads",
                "diskio_writes",
                "diskio_read_bytes",
                "diskio_write_bytes",
                "diskio_read_time",
                "diskio_write_time",
                "mem_used_percent",
                "mem_available_percent",
                "mem_cached",
                "mem_buffers",
                "mem_free",
                "mem_used",
                "mem_total",
                "mem_available",
                "netstat_tcp_established",
                "netstat_tcp_time_wait",
                "netstat_tcp_close",
                "netstat_tcp_close_wait",
                "netstat_tcp_closing",
                "net_bytes_sent",
                "net_bytes_recv",
                "net_packets_sent",
                "net_packets_recv",
                "net_err_in",
                "net_err_out",
                "net_drop_in",
                "net_drop_out",
                "processes_running",
                "processes_sleeping",
                "processes_stopped",
                "processes_zombies",
                "processes_blocked",
                "processes_paging",
                "processes_total",
                "swap_used_percent",
                "swap_free",
                "swap_used",
                "swap_total",
            }

            # Filter for truly custom namespaces and metrics
            for metric in all_metrics:
                namespace = metric.get("Namespace", "")
                metric_name = metric.get("MetricName", "")

                # Skip AWS namespaces and AWS-generated namespaces
                if (
                    namespace.startswith("AWS/")
                    or namespace in aws_generated_namespaces
                ):
                    continue

                # For CWAgent namespace, only include non-system metrics (custom application metrics)
                if namespace == "CWAgent" and metric_name in cwagent_system_metrics:
                    continue

                # This is a truly custom metric
                custom_metrics.append(metric)
                custom_namespaces.add(namespace)

            return {
                "custom_namespaces": list(custom_namespaces),
                "total_custom_metrics": len(custom_metrics),
                "sample_metrics": custom_metrics[:5],  # First 5 for examples
            }

        except Exception:
            return None

    def execute_app_signals_list_services_check(self):
        """List Application Signals services with required time window"""
        try:
            from datetime import datetime, timedelta, timezone

            end = datetime.now(timezone.utc)
            start = end - timedelta(hours=1)
            cmd = f"aws application-signals list-services --start-time {start.strftime('%Y-%m-%dT%H:%M:%SZ')} --end-time {end.strftime('%Y-%m-%dT%H:%M:%SZ')} --output json"
            result = self.run_aws_command(cmd)
            if result is None:
                return None
            return {"Services": result.get("ServiceSummaries", [])}
        except Exception:
            return None
