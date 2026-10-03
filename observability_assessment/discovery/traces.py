# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0


class TracesDiscoveryMixin:
    """Collect X-Ray tracing and instrumentation signals."""

    def execute_xray_service_graph_check(self):
        """Check X-Ray service graph with time range"""
        try:
            import time

            end_time = int(time.time())
            start_time = end_time - (6 * 60 * 60)  # Look back over the last 6 hours

            result = self.run_aws_command(
                f"aws xray get-service-graph --start-time {start_time} --end-time {end_time} --output json"
            )
            return result

        except Exception:
            return None

    def execute_xray_sampling_rules_check(self):
        """Check X-Ray sampling rules, excluding default rule"""
        try:
            result = self.run_aws_command("aws xray get-sampling-rules --output json")
            if result is None:
                return None
            # Return only custom rules; an empty list is a real "no custom
            # rules" answer, distinct from a failed call (None).
            custom_rules = [
                rule
                for rule in result.get("SamplingRuleRecords", [])
                if rule.get("SamplingRule", {}).get("RuleName") != "Default"
            ]
            return {"SamplingRuleRecords": custom_rules}

        except Exception:
            return None

    def execute_xray_insights_check(self):
        """Check X-Ray groups for Insights configuration and recent insight summaries."""
        try:
            groups = self.run_aws_command("aws xray get-groups --output json")
            if groups is None:
                return None
            insights_groups = [
                g
                for g in groups.get("Groups", [])
                if g.get("InsightsConfiguration", {}).get("InsightsEnabled")
            ]
            notifications_groups = [
                g
                for g in insights_groups
                if g.get("InsightsConfiguration", {}).get("NotificationsEnabled")
            ]
            import time

            end = int(time.time())
            start = end - 86400
            summaries = self.run_aws_command(
                f"aws xray get-insight-summaries --start-time {start} --end-time {end} --output json"
            )
            insight_count = len((summaries or {}).get("InsightSummaries", []))
            return {
                "insights_enabled_groups": len(insights_groups),
                "notifications_enabled_groups": len(notifications_groups),
                "group_names": [g["GroupName"] for g in insights_groups],
                "recent_insights": insight_count,
                # A failed summaries call leaves recent_insights unknown.
                "failed_lookups": 1 if summaries is None else 0,
            }
        except Exception:
            return None

    def execute_xray_custom_annotations_check(self):
        """Check for custom annotations on recent traces indicating manual instrumentation"""
        try:
            import time

            end = int(time.time())
            start = end - 21600  # 6 hours
            result = self.run_aws_command(
                f"aws xray get-trace-summaries --start-time {start} --end-time {end} "
                f'--sampling-strategy \'{{"Name":"FixedRate","Value":0.5}}\' --output json'
            )
            if result is None:
                return None
            if "TraceSummaries" not in result:
                return {
                    "total_traces": 0,
                    "traces_with_custom_annotations": 0,
                    "custom_annotation_keys": [],
                }

            # Auto-generated annotation prefixes to exclude
            auto_prefixes = (
                "aws:",
                "span.",
                "otel.",
                "http.",
                "rpc.",
                "db.",
                "net.",
                "messaging.",
            )
            summaries = result["TraceSummaries"]
            custom_keys = set()
            traces_with_custom = 0
            for t in summaries:
                annotations = t.get("Annotations") or {}
                trace_custom = [
                    k
                    for k in annotations
                    if not any(
                        k.startswith(p) or k == p.rstrip(".") for p in auto_prefixes
                    )
                ]
                if trace_custom:
                    traces_with_custom += 1
                    custom_keys.update(trace_custom)

            return {
                "total_traces": len(summaries),
                "traces_with_custom_annotations": traces_with_custom,
                "custom_annotation_keys": sorted(custom_keys),
            }
        except Exception:
            return None
