# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
from types import MappingProxyType

from observability_assessment.reporting.evidence import esc
from observability_assessment.text import plural

from .check_specs import CHECK_SPECS

logger = logging.getLogger("observability_assessment")

ERROR_SUMMARY_LIMIT = 300


def last_error_summary(error):
    """The line of an AWS CLI error that names the cause, truncated for the report.

    The CLI follows the error with usage and help lines, so the first line
    mentioning an error is used, falling back to the last non-empty line.
    """
    lines = [line.strip() for line in (error or "").splitlines() if line.strip()]
    if not lines:
        return ""
    summary = next((line for line in lines if "error" in line.lower()), lines[-1])
    if len(summary) > ERROR_SUMMARY_LIMIT:
        summary = summary[: ERROR_SUMMARY_LIMIT - 3] + "..."
    return summary


CUSTOM_HANDLERS = MappingProxyType(
    {
        "custom_ec2_cloudwatch_agent_check": "execute_ec2_cloudwatch_agent_check",
        "custom_lambda_json_logging_check": "execute_lambda_json_logging_check",
        "custom_ecs_task_log_check": "execute_ecs_task_log_check",
        "custom_eks_control_plane_logs_check": "execute_eks_control_plane_logs_check",
        "custom_field_indexes_per_log_group_check": "execute_field_indexes_per_log_group_check",
        "custom_eks_addons_check": "execute_eks_addons_check",
        "custom_ecs_container_insights_check": "execute_ecs_container_insights_check",
        "custom_lambda_insights_check": "execute_lambda_insights_check",
        "custom_metrics_namespaces_check": "execute_custom_metrics_namespaces_check",
        "custom_cloudwatch_alarms_check": "execute_cloudwatch_alarms_check",
        "custom_log_export_tasks_per_log_group_check": "execute_log_export_tasks_per_log_group_check",
        "custom_top_log_groups_retention_check": "execute_top_log_groups_retention_check",
        "custom_subscription_filters_coverage_check": "execute_subscription_filters_coverage_check",
        "custom_log_centralization_analysis_check": "execute_log_centralization_analysis_check",
        "custom_oam_links_and_sinks_check": "execute_oam_links_and_sinks_check",
        "custom_json_structured_logs_check": "execute_json_structured_logs_check",
        "custom_alarm_sns_configuration_check": "execute_alarm_sns_configuration_check",
        "custom_anomaly_detection_bands_check": "execute_anomaly_detection_bands_check",
        "custom_alarm_opsitem_actions_check": "execute_alarm_opsitem_actions_check",
        "custom_devops_agent_spaces_check": "execute_devops_agent_spaces_check",
        "custom_alarm_lambda_actions_check": "execute_alarm_lambda_actions_check",
        "custom_alarm_investigations_actions_check": "execute_alarm_investigations_actions_check",
        "custom_alarm_ec2_actions_check": "execute_alarm_ec2_actions_check",
        "custom_dashboard_variables_check": "execute_dashboard_variables_check",
        "custom_xray_service_graph_check": "execute_xray_service_graph_check",
        "custom_xray_sampling_rules_check": "execute_xray_sampling_rules_check",
        "custom_log_groups_categorization_check": "execute_log_groups_categorization_check",
        "custom_log_group_tags_check": "execute_log_group_tags_check",
        "custom_stale_log_groups_check": "execute_stale_log_groups_check",
        "custom_app_signals_list_services_check": "execute_app_signals_list_services_check",
        "custom_xray_custom_annotations_check": "execute_xray_custom_annotations_check",
        "custom_xray_insights_check": "execute_xray_insights_check",
        "custom_cloudwatch_omni_spaces_check": "execute_cloudwatch_omni_spaces_check",
        "custom_cloudwatch_omni_integrations_check": "execute_cloudwatch_omni_integrations_check",
    }
)


def _validate_custom_handlers() -> None:
    catalog_commands = {
        spec.command for spec in CHECK_SPECS if spec.command.startswith("custom_")
    }
    if set(CUSTOM_HANDLERS) != catalog_commands:
        missing = catalog_commands - set(CUSTOM_HANDLERS)
        extra = set(CUSTOM_HANDLERS) - catalog_commands
        raise ValueError(
            f"Custom discovery handler mismatch: missing={missing}, extra={extra}"
        )


_validate_custom_handlers()


class DiscoveryExecutorMixin:
    """Dispatch discovery checks to AWS commands or custom collectors."""

    def execute_discovery_check(self, check_id: int):
        """Execute a specific discovery check"""
        check = next(
            (c for c in self.results.discovery_checks if c.id == check_id), None
        )
        if not check:
            return

        from datetime import datetime

        start_time = datetime.now().strftime("%H:%M:%S")
        print(
            f"  [{start_time}] Running check #{check.id}: {check.name}...", flush=True
        )

        try:
            if check.command.startswith("custom_"):
                handler_name = CUSTOM_HANDLERS.get(check.command)
                if handler_name is None:
                    raise ValueError(
                        f"Unknown custom discovery command: {check.command}"
                    )
                handler = getattr(self, handler_name, None)
                if not callable(handler):
                    raise TypeError(f"Missing custom discovery handler: {handler_name}")
                check.result = handler()
            else:
                check.result = self.run_aws_command(check.command)

            if check.result is not None:
                check.status = "success"
                # Export to CSV for built-in checks
                if 1 <= check.id <= len(CHECK_SPECS):
                    # A CSV write failure is a reporting problem, not an
                    # evaluation failure, so it must not discard the result.
                    try:
                        self.export_check_result_to_csv(check)
                    except Exception as e:
                        logger.warning(
                            "Could not export check #%s to CSV: %s", check.id, e
                        )
                # Generate detailed evidence based on check type
                try:
                    check.evidence = self.generate_detailed_evidence(check)
                except Exception as e:
                    logger.debug(
                        "Exception in evidence generation for %s: %s", check.name, e
                    )
                    check.evidence = f"Account: {self.results.account_id}, Region: {self.region} - Evidence generation failed: {str(e)}"
                failed = (
                    check.result.get("failed_lookups", 0)
                    if isinstance(check.result, dict)
                    else 0
                )
                if failed:
                    check.evidence += (
                        f"<br><strong>Partial data:</strong> {plural(failed, 'resource lookup or probe', 'resource lookups or probes')} "
                        "failed. The available result may be incomplete."
                    )
            else:
                # run_aws_command returns None on command failure/error and {} on a
                # successful-but-empty result, so None here means the check could not
                # be evaluated (e.g. permissions, throttling, CLI error) rather than
                # "no resources". Mark it "error" so scoring/reporting can tell them apart.
                check.status = "error"
                aws_error = last_error_summary(getattr(self, "last_aws_error", ""))
                if aws_error:
                    check.evidence = (
                        f"Check could not be evaluated. AWS CLI error: {esc(aws_error)} "
                        "Re-run with --debug for details."
                    )
                else:
                    check.evidence = (
                        "Check could not be evaluated (AWS command returned no result -- "
                        "likely a permissions, throttling, or CLI error). Re-run with --debug "
                        "for details."
                    )
                logger.warning(
                    "Check #%s (%s) could not be evaluated -- %s",
                    check.id,
                    check.name,
                    aws_error or "no result returned",
                )
                # Export errored checks to CSV as well
                if 1 <= check.id <= len(CHECK_SPECS):
                    try:
                        self.export_unavailable_check_to_csv(
                            check, aws_error or "no result returned"
                        )
                    except Exception as e:
                        logger.warning(
                            "Could not export check #%s to CSV: %s", check.id, e
                        )
        except Exception as e:
            check.status = "error"
            # Drop any partial result so nothing downstream scores it.
            check.result = None
            check.evidence = f"Check failed with an unexpected error: {e}"
            if 1 <= check.id <= len(CHECK_SPECS):
                try:
                    self.export_unavailable_check_to_csv(check, "unexpected error")
                except Exception:
                    logger.debug("Could not export errored check #%s to CSV", check.id)
            logger.warning(
                "Unexpected error executing check #%s (%s): %s",
                check.id,
                check.name,
                e,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )

    def execute_all_discovery_checks(self):
        """Execute all discovery checks"""
        print(f"Executing {len(self.results.discovery_checks)} discovery checks...")

        for i, check in enumerate(self.results.discovery_checks, 1):
            self.execute_discovery_check(check.id)

        successful_checks = len(
            [c for c in self.results.discovery_checks if c.status == "success"]
        )
        errored_checks = [
            c for c in self.results.discovery_checks if c.status == "error"
        ]
        print(
            f"[OK] Discovery complete: {successful_checks}/{len(self.results.discovery_checks)} checks successful"
        )
        if errored_checks:
            print(
                f"[WARN] {plural(len(errored_checks), 'check')} could not be evaluated (errors, not empty results). "
                f"Re-run with --debug for details:"
            )
            for c in errored_checks:
                print(f"     - #{c.id}: {c.name}")
