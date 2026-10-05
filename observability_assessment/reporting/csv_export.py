# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CSV exports for discovery check results."""

import csv
import json
import os
from functools import partial

# Row labels for checks whose CSV label differs from the truncated check name.
# Shared by evaluated and unavailable rows so a check keeps one label.
CSV_LABELS = {
    1: "Log Groups Categorization",
    2: "Log Groups Retention Policies",
    3: "Logs Insights Query Definitions",
    4: "Logs Insights Query History",
    5: "Metric Filters",
    6: "Subscription Filters",
    7: "EC2 CloudWatch agent",
    8: "Lambda JSON Structured Logging",
    9: "ECS Task Logging Configured",
    10: "EKS Clusters With All Control Plane Logs",
    11: "EKS CloudWatch Observability Add-on",
    15: "CloudWatch Cross-Account Observability",
    51: "CloudWatch Omni Spaces",
    52: "CloudWatch Omni Integrations",
}

_FORMULA_PREFIXES = ("=", "+", "-", "@", "＝", "＋", "－", "＠")
_LEADING_CONTROLS = str.maketrans({"\t": r"\t", "\r": r"\r", "\n": r"\n"})


def _spreadsheet_safe_cell(value):
    """Keep text fields as text when the CSV is opened in a spreadsheet.

    Tabs added to formula-leading fields remain in programmatic CSV reads.
    Leading control characters are made visible before checking for formulas.
    """
    if not isinstance(value, str):
        return value
    leading_length = len(value) - len(value.lstrip(" \t\r\n"))
    if leading_length:
        value = (
            value[:leading_length].translate(_LEADING_CONTROLS) + value[leading_length:]
        )
    if value.lstrip(" ").startswith(_FORMULA_PREFIXES):
        return "\t" + value
    return value


def csv_label(check):
    """CSV row label for a discovery check."""
    return CSV_LABELS.get(check.id, check.name[:50])


class CsvReportingMixin:
    def export_check_to_csv(
        self, check_name, found_count, total_count, details=None, status="Evaluated"
    ):
        """Export check results to CSV file.

        ``status`` is "Evaluated", "Partial" (some resources could not be
        read), or "Unavailable" (the check could not run; counts are blank so
        the row cannot be mistaken for zero resources).
        """
        if not self.csv_file:
            # Include the account ID (like the HTML report) so concurrent
            # multi-account workers that start within the same second do not
            # append to — and corrupt — one another's CSV export.
            self.csv_file = f"assessment-result/discovery_checks_{self.timestamp}_{self.results.account_id}.csv"
            os.makedirs("assessment-result", exist_ok=True)
            # Create CSV with headers
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                writer.writerow(
                    [
                        "Check Name",
                        "Found Count",
                        "Total Count",
                        "Percentage",
                        "Details",
                        "Status",
                    ]
                )

        details_str = json.dumps(details) if details else ""
        if status == "Unavailable":
            found_count = total_count = percentage_str = ""
        else:
            percentage = (found_count / total_count * 100) if total_count > 0 else 0
            percentage_str = f"{percentage:.1f}%"

        with open(self.csv_file, "a", newline="") as f:
            # Keep the neutralizing tab inside one quoted spreadsheet cell.
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            writer.writerow(
                [
                    _spreadsheet_safe_cell(check_name),
                    found_count,
                    total_count,
                    percentage_str,
                    _spreadsheet_safe_cell(details_str),
                    _spreadsheet_safe_cell(status),
                ]
            )

    def export_unavailable_check_to_csv(self, check, reason=""):
        """Record a check that could not be evaluated."""
        self.export_check_to_csv(
            csv_label(check),
            0,
            0,
            {"reason": reason} if reason else None,
            status="Unavailable",
        )

    def export_check_result_to_csv(self, check):
        """Extract counts from check result and export to CSV"""
        failed = (
            check.result.get("failed_lookups", 0)
            if isinstance(check.result, dict)
            else 0
        )
        export = partial(
            self.export_check_to_csv, status="Partial" if failed else "Evaluated"
        )
        if check.id == 1:
            # Already handled in execute_log_groups_categorization_check
            return
        elif check.id == 2:
            # Already handled in execute_top_log_groups_retention_check
            return
        elif check.id == 3:
            # Query definitions
            defs = (
                check.result.get("queryDefinitions", [])
                if isinstance(check.result, dict)
                else []
            )
            count = len(defs)
            export(
                "Logs Insights Query Definitions",
                1 if count > 0 else 0,
                1,
                {"count": count},
            )
        elif check.id == 4:
            # Query history
            queries = (
                check.result.get("queries", [])
                if isinstance(check.result, dict)
                else []
            )
            count = len(queries)
            export(
                "Logs Insights Query History",
                1 if count > 0 else 0,
                1,
                {"count": count},
            )
        elif check.id == 5:
            # Metric filters
            filters = (
                check.result.get("metricFilters", [])
                if isinstance(check.result, dict)
                else []
            )
            count = len(filters)
            export("Metric Filters", 1 if count > 0 else 0, 1, {"count": count})
        elif check.id == 6:
            # Subscription filters
            if isinstance(check.result, dict):
                found = check.result.get("groups_with_subscription_filters", 0)
                total = check.result.get("total_log_groups", 0)
                export(
                    "Subscription Filters",
                    1 if found > 0 else 0,
                    1,
                    {"log_groups_with_subscriptions": found, "total_log_groups": total},
                )
        elif check.id == 7:
            # EC2 CloudWatch agent - handled in custom function
            if isinstance(check.result, dict):
                found = check.result.get("logging_configured_count", 0)
                total = check.result.get("total_instances", 0)
                # The logging count is measured on only a sample of SSM-managed
                # instances (SSM send-command is slow), so found/total can
                # understate real coverage. Record the sampling in the CSV
                # details so the percentage isn't read as an exhaustive census.
                ssm_count = len(check.result.get("ssm_instances", []))
                sampled_count = check.result.get("ssm_sampled_count", ssm_count)
                details = None
                if ssm_count > sampled_count:
                    details = {
                        "sampled": True,
                        "ssm_instances_probed": sampled_count,
                        "ssm_instances_total": ssm_count,
                        "sample_limit": check.result.get("ssm_sample_limit"),
                        "note": (
                            "Logging count measured on a sample of SSM-managed "
                            "instances; percentage is indicative, not exhaustive."
                        ),
                    }
                export("EC2 CloudWatch agent", found, total, details=details)
        elif check.id == 8:
            # Lambda JSON logging
            if isinstance(check.result, dict):
                found = check.result.get("json_logging_count", 0)
                total = check.result.get("total_functions", 0)
                export("Lambda JSON Structured Logging", found, total)
        elif check.id == 9:
            # ECS structured logging - handled in custom function
            if isinstance(check.result, dict):
                found = check.result.get("logging_configured_count", 0)
                total = check.result.get("total_tasks", 0)
                export("ECS Task Logging Configured", found, total)
        elif check.id == 10:
            # EKS control plane logs
            if isinstance(check.result, dict):
                enabled = check.result.get("clusters_all_enabled", 0)
                total = len(check.result.get("clusters", []))
                export("EKS Clusters With All Control Plane Logs", enabled, total)
        elif check.id == 11:
            # EKS CloudWatch Observability add-on
            if isinstance(check.result, dict):
                obs = check.result.get("observability_clusters", 0)
                total = check.result.get("total_clusters", 0)
                export(
                    "EKS CloudWatch Observability Add-on",
                    obs,
                    total if total > 0 else 1,
                )
            else:
                export("EKS CloudWatch Observability Add-on", 0, 1)
        elif check.id == 15:
            # CloudWatch cross-account observability (OAM)
            if isinstance(check.result, dict):
                links = check.result.get("links_count", 0)
                sinks = check.result.get("sinks_count", 0)
                has_oam = links > 0 or sinks > 0
                export(
                    "CloudWatch Cross-Account Observability",
                    1 if has_oam else 0,
                    1,
                    {"links": links, "sinks": sinks},
                )
            else:
                export("CloudWatch Cross-Account Observability", 0, 1)
        elif check.id == 51:
            # CloudWatch Omni spaces: active spaces out of all spaces found
            if isinstance(check.result, dict):
                active = check.result.get("active_spaces", 0)
                total = check.result.get("total_spaces", 0)
                export(
                    "CloudWatch Omni Spaces",
                    active,
                    total if total > 0 else 1,
                    {
                        "organization_domain": check.result.get(
                            "has_organization_domain", False
                        )
                    },
                )
            else:
                export("CloudWatch Omni Spaces", 0, 1)
        elif check.id == 52:
            # CloudWatch Omni integrations: active integrations out of all found
            if isinstance(check.result, dict):
                active = check.result.get("active_integrations", 0)
                total = check.result.get("total_integrations", 0)
                export(
                    "CloudWatch Omni Integrations",
                    active,
                    total if total > 0 else 1,
                    check.result.get("active_by_type", {}),
                )
            else:
                export("CloudWatch Omni Integrations", 0, 1)
        elif check.id == 29:
            # Transaction Search: spans must be going to CloudWatch Logs
            result = check.result if isinstance(check.result, dict) else {}
            active = (
                result.get("Destination") == "CloudWatchLogs"
                and result.get("Status") == "ACTIVE"
            )
            export(
                csv_label(check),
                1 if active else 0,
                1,
                {k: result[k] for k in ("Destination", "Status") if k in result},
            )
        else:
            # Default handler for checks 12-50: binary yes/no based on result existence
            if check.id >= 12 and check.id <= 50:
                # Extract check name from the check object
                check_name = csv_label(check)
                # Binary: 1 if the result holds data. An empty-but-successful
                # response such as {"Canaries": []} is a "no".
                if isinstance(check.result, dict):
                    has_result = any(
                        value not in (None, "", [], {})
                        for key, value in check.result.items()
                        if key != "NextToken"
                    )
                elif isinstance(check.result, list):
                    has_result = len(check.result) > 0
                else:
                    has_result = isinstance(check.result, (str, int, float, bool))
                export(check_name, 1 if has_result else 0, 1)
