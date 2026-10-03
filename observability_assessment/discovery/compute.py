# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import logging

logger = logging.getLogger("observability_assessment")


class ComputeDiscoveryMixin:
    """Collect observability signals from EC2, Lambda, ECS, and EKS."""

    def execute_ec2_cloudwatch_agent_check(self):
        """Custom check for EC2 CloudWatch agent - SSM agent, CW agent deployment, and logging config"""
        try:
            # Step 1: Get all EC2 instances
            ec2_result = self.run_aws_command(
                "aws ec2 describe-instances --output json"
            )
            # run_aws_command returns None on command error and {} / a dict on
            # success. None here means the check could not be evaluated, so
            # propagate None to let execute_discovery_check mark it "error"
            # rather than silently reporting "no resources".
            if ec2_result is None:
                return None
            if "Reservations" not in ec2_result:
                return {
                    "instances": [],
                    "ssm_instances": [],
                    "cw_agent_instances": [],
                    "logging_configured_instances": [],
                }

            # Extract all instances
            all_instances = []
            for reservation in ec2_result["Reservations"]:
                all_instances.extend(reservation.get("Instances", []))

            # Filter running instances
            running_instances = [
                inst
                for inst in all_instances
                if inst.get("State", {}).get("Name") == "running"
            ]

            if not running_instances:
                return {
                    "instances": [],
                    "ssm_instances": [],
                    "cw_agent_instances": [],
                    "logging_configured_instances": [],
                }

            # Step 2: Check SSM agent status for running instances
            instance_ids = [inst.get("InstanceId") for inst in running_instances]
            ssm_instances = []

            ssm_result = self.run_aws_command(
                "aws ssm describe-instance-information --output json"
            )
            # Without the SSM inventory the agent cannot be probed at all, so
            # the check cannot be evaluated.
            if ssm_result is None:
                return None
            ssm_instance_ids = [
                info.get("InstanceId")
                for info in ssm_result.get("InstanceInformationList", [])
            ]
            ssm_instances = [
                inst_id for inst_id in instance_ids if inst_id in ssm_instance_ids
            ]

            # Step 3: Check CloudWatch agent status on SSM-enabled instances.
            # SSM send-command + polling is slow, so we probe only a sample of
            # the SSM-managed instances. sampled_count is surfaced in the
            # evidence so coverage percentages aren't read as exhaustive.
            SSM_SAMPLE_LIMIT = 5
            cw_agent_instances = []
            logging_configured_instances = []
            failed_probes = []
            sampled_instances = ssm_instances[:SSM_SAMPLE_LIMIT]

            for instance_id in sampled_instances:
                try:
                    # Check multiple ways CloudWatch agent can be running
                    command_result = self.run_aws_command(
                        f'aws ssm send-command --instance-ids {self._sanitize(instance_id)} --document-name "AWS-RunShellScript" --parameters \'commands=["pgrep -f amazon-cloudwatch-agent >/dev/null && echo PROCESS_RUNNING || echo PROCESS_NOT_RUNNING","systemctl is-active amazon-cloudwatch-agent 2>/dev/null || echo SERVICE_NOT_ACTIVE","ps aux | grep -E cloudwatch | grep -v grep | wc -l"]\' --output json'
                    )
                    if not command_result or "Command" not in command_result:
                        failed_probes.append(instance_id)
                        continue

                    # Poll for SSM command completion. The probe script always
                    # exits 0, so anything other than Success means the probe
                    # itself did not run and the agent state is unknown.
                    output_result = self._poll_ssm_command(
                        command_result["Command"]["CommandId"], instance_id
                    )
                    if not output_result or output_result.get("Status") != "Success":
                        failed_probes.append(instance_id)
                        continue

                    stdout = output_result.get("StandardOutputContent", "")
                    logger.debug(
                        "Instance %s CW agent check output: %s",
                        instance_id,
                        repr(stdout[:100]),
                    )

                    # Check if agent is running (process, service, or
                    # container). Match tokens exactly per line: the
                    # probe emits SERVICE_NOT_ACTIVE / "inactive" when the
                    # agent is stopped, so a substring test for "active"
                    # would count stopped agents as running. `systemctl
                    # is-active` prints exactly "active" on its own line.
                    probe_lines = [line.strip() for line in stdout.split("\n")]
                    if not (
                        "PROCESS_RUNNING" in probe_lines
                        or "active" in [line.lower() for line in probe_lines]
                        or any(int(line) > 0 for line in probe_lines if line.isdigit())
                    ):
                        continue

                    logger.debug("Instance %s has CW agent running", instance_id)
                    cw_agent_instances.append(instance_id)

                    # Step 4: Check for actual log collection configuration (not agent's own logs)
                    config_command = self.run_aws_command(
                        f'aws ssm send-command --instance-ids {self._sanitize(instance_id)} --document-name "AWS-RunShellScript" --parameters \'commands=["find /opt/aws/amazon-cloudwatch-agent/etc/ -name *.json -exec grep -l log_group_name {{}} \\\\; 2>/dev/null | wc -l"]\' --output json'
                    )
                    if not config_command or "Command" not in config_command:
                        failed_probes.append(instance_id)
                        continue
                    config_output = self._poll_ssm_command(
                        config_command["Command"]["CommandId"], instance_id
                    )
                    if not config_output or config_output.get("Status") != "Success":
                        failed_probes.append(instance_id)
                        continue

                    config_content = config_output.get("StandardOutputContent", "")

                    # Check if actual log collection configuration is found (not just agent logs)
                    config_lines = config_content.strip().split("\n")
                    logger.debug(
                        "Instance %s config content: %s",
                        instance_id,
                        repr(config_content[:200]),
                    )
                    # First line should be the count, check if it's > 0
                    first_line = config_lines[0].strip() if config_lines else ""
                    if first_line.isdigit() and int(first_line) > 0:
                        logger.debug(
                            "Adding %s to logging_configured_instances", instance_id
                        )
                        logging_configured_instances.append(instance_id)
                except Exception:
                    failed_probes.append(instance_id)

            return {
                "instances": instance_ids,
                "failed_lookups": len(failed_probes),
                "failed_probe_instances": failed_probes,
                "ssm_instances": ssm_instances,
                "cw_agent_instances": cw_agent_instances,
                "logging_configured_instances": logging_configured_instances,
                "total_instances": len(instance_ids),
                "logging_configured_count": len(logging_configured_instances),
                "ssm_sampled_count": len(sampled_instances),
                "ssm_sample_limit": SSM_SAMPLE_LIMIT,
            }

        except Exception as e:
            # An unexpected failure means the check could not be evaluated;
            # return None so it is marked "error" rather than "no resources".
            logger.debug("EC2 CloudWatch agent check failed: %s", e)
            return None

    def execute_lambda_json_logging_check(self):
        """Check Lambda functions for JSON structured logging configuration.

        list-functions returns each function's LoggingConfig and Environment,
        so every function is evaluated without a per-function lookup.
        """
        try:
            functions_result = self.run_aws_command(
                "aws lambda list-functions --output json"
            )
            if functions_result is None:
                return None
            functions = functions_result.get("Functions", [])
            functions_with_json = []

            for func in functions:
                # Native Lambda structured logging (LoggingConfig.LogFormat) is
                # the canonical signal; AWS_LAMBDA_LOG_FORMAT is set inside the
                # runtime, not in configured env vars.
                log_format = func.get("LoggingConfig", {}).get("LogFormat", "")
                env_vars = func.get("Environment", {}).get("Variables", {})
                # Fall back to library-level JSON logging indicators
                json_indicators = [
                    log_format.upper() == "JSON",
                    "json" in env_vars.get("LOG_FORMAT", "").lower(),
                    "json" in env_vars.get("LOGGING_FORMAT", "").lower(),
                    "JSON" in env_vars.get("LOG_LEVEL", "").upper(),
                    "json" in env_vars.get("POWERTOOLS_LOG_FORMAT", "").lower(),
                ]
                if any(json_indicators):
                    functions_with_json.append(func.get("FunctionName", ""))

            return {
                "total_functions": len(functions),
                "failed_lookups": 0,
                "json_logging_count": len(functions_with_json),
                "functions_with_json": functions_with_json,
            }

        except Exception:
            return None

    def execute_ecs_task_log_check(self):
        """Custom check for ECS running tasks and their logging configuration"""
        try:
            # Step 1: Get ECS clusters
            clusters_result = self.run_aws_command(
                "aws ecs list-clusters --output json"
            )
            if clusters_result is None:
                return None
            if "clusterArns" not in clusters_result:
                return {
                    "running_tasks": [],
                    "tasks_with_logging": [],
                    "clusters": [],
                    "logging_configs": [],
                }

            clusters = clusters_result["clusterArns"]
            all_running_tasks = []
            tasks_with_logging = []
            logging_configs = []
            # Tasks whose configuration could not be read are unknown, so they
            # are kept out of running_tasks (the coverage denominator).
            failed_lookups = 0

            # Step 2: For each cluster, get running tasks
            for cluster in clusters[:3]:  # Limit to first 3 clusters for performance
                try:
                    tasks_result = self.run_aws_command(
                        f"aws ecs list-tasks --cluster {self._sanitize(cluster)} --desired-status RUNNING --output json"
                    )
                    if tasks_result is None:
                        failed_lookups += 1
                        continue
                    task_arns = tasks_result.get("taskArns", [])

                    # Step 3: Get task details to find task definition.
                    # describe-tasks accepts up to 100 tasks per call.
                    for i in range(0, len(task_arns), 100):
                        batch = task_arns[i : i + 100]
                        tasks_detail = self.run_aws_command(
                            f"aws ecs describe-tasks --cluster {self._sanitize(cluster)} --tasks {' '.join(self._sanitize(a) for a in batch)} --output json"
                        )
                        if tasks_detail is None:
                            failed_lookups += len(batch)
                            continue

                        for task in tasks_detail.get("tasks", []):
                            task_arn = task.get("taskArn", "")
                            task_def_arn = task.get("taskDefinitionArn", "")
                            if not task_def_arn:
                                continue
                            # Step 4: Check task definition for logging configuration
                            task_def_result = self.run_aws_command(
                                f"aws ecs describe-task-definition --task-definition {self._sanitize(task_def_arn)} --output json"
                            )
                            if (
                                task_def_result is None
                                or "taskDefinition" not in task_def_result
                            ):
                                failed_lookups += 1
                                continue
                            all_running_tasks.append(task_arn)

                            task_def = task_def_result["taskDefinition"]
                            task_def_name = task_def.get("family", "Unknown")
                            containers = task_def.get("containerDefinitions", [])

                            # Check each container's logging configuration
                            has_logging = False
                            container_configs = []
                            for container in containers:
                                container_name = container.get("name", "Unknown")
                                log_config = container.get("logConfiguration", {})
                                if log_config:
                                    log_driver = log_config.get("logDriver", "none")
                                    container_configs.append(
                                        {
                                            "container": container_name,
                                            "logDriver": log_driver,
                                            "options": log_config.get("options", {}),
                                        }
                                    )
                                    if log_driver in [
                                        "awslogs",
                                        "awsfirelens",
                                        "json-file",
                                        "syslog",
                                    ]:
                                        has_logging = True
                                else:
                                    container_configs.append(
                                        {
                                            "container": container_name,
                                            "logDriver": "none",
                                            "options": {},
                                        }
                                    )

                            logging_configs.append(
                                {
                                    "taskDefinition": task_def_name,
                                    "taskDefArn": task_def_arn,
                                    "containers": container_configs,
                                }
                            )

                            if has_logging:
                                tasks_with_logging.append(task_arn)
                except Exception:
                    failed_lookups += 1

            # Every lookup that ran failed, so task logging is unknown, not absent.
            if clusters and not all_running_tasks and failed_lookups:
                return None

            return {
                "clusters": clusters,
                "running_tasks": all_running_tasks,
                "tasks_with_logging": tasks_with_logging,
                "logging_configs": logging_configs,
                "total_tasks": len(all_running_tasks),
                # A log driver shows logs are shipped, not that the application
                # emits JSON, so this is not reported as structured logging.
                "logging_configured_count": len(tasks_with_logging),
                "failed_lookups": failed_lookups,
            }

        except Exception:
            return None

    def execute_eks_control_plane_logs_check(self):
        """Check if all 5 EKS control plane log types are enabled"""
        try:
            # Get list of EKS clusters
            clusters_result = self.run_aws_command(
                "aws eks list-clusters --output json"
            )
            if clusters_result is None:
                return None
            if "clusters" not in clusters_result:
                return {"clusters": [], "enabled_types": 0, "total_types": 5}

            clusters = clusters_result["clusters"]
            required_types = {
                "api",
                "audit",
                "authenticator",
                "controllerManager",
                "scheduler",
            }
            all_enabled_types = set()
            cluster_configs = []
            failed_clusters = []

            # Check each cluster's logging configuration
            for cluster_name in clusters[:5]:  # Limit to first 5 clusters
                try:
                    cluster_result = self.run_aws_command(
                        f"aws eks describe-cluster --name {self._sanitize(cluster_name)} --output json"
                    )
                    if cluster_result is None or "cluster" not in cluster_result:
                        failed_clusters.append(cluster_name)
                        continue
                    logging_config = cluster_result["cluster"].get("logging", {})
                    cluster_logging = logging_config.get("clusterLogging", [])

                    enabled_types = set()
                    for log_config in cluster_logging:
                        if log_config.get("enabled", False):
                            enabled_types.update(log_config.get("types", []))

                    all_enabled_types.update(enabled_types)
                    cluster_configs.append(
                        {
                            "cluster": cluster_name,
                            "enabled_types": list(enabled_types),
                            "all_enabled": enabled_types >= required_types,
                        }
                    )
                except Exception:
                    failed_clusters.append(cluster_name)

            # Every sampled cluster was unreadable: nothing can be concluded.
            if clusters and not cluster_configs and failed_clusters:
                return None

            clusters_all_enabled = sum(1 for c in cluster_configs if c["all_enabled"])
            # enabled_types is the union across sampled clusters (any control
            # plane logging); the all-five verdict must hold per cluster.
            return {
                "clusters": cluster_configs,
                "failed_lookups": len(failed_clusters),
                "enabled_types": len(all_enabled_types & required_types),
                "total_types": 5,
                "clusters_all_enabled": clusters_all_enabled,
                "all_types_enabled": bool(cluster_configs)
                and clusters_all_enabled == len(cluster_configs),
            }

        except Exception:
            return None

    def execute_ecs_container_insights_check(self):
        """Custom check for Container Insights across all ECS clusters.

        Enumerates clusters via list-clusters (rather than a hardcoded name),
        then describes them with SETTINGS. Returns the raw describe-clusters
        shape ({"clusters": [...]}) so the evidence and scoring consumers can
        read each cluster's ``settings`` list unchanged.
        """
        try:
            clusters_result = self.run_aws_command(
                "aws ecs list-clusters --output json"
            )
            if clusters_result is None:
                return None
            if not clusters_result.get("clusterArns"):
                return {"clusters": []}

            cluster_arns = clusters_result["clusterArns"]
            all_clusters = []
            failed_lookups = 0

            # describe-clusters accepts up to 100 cluster identifiers per call.
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i : i + 100]
                quoted = " ".join(self._sanitize(arn) for arn in batch)
                described = self.run_aws_command(
                    f"aws ecs describe-clusters --clusters {quoted} --include SETTINGS --output json"
                )
                if described is None:
                    failed_lookups += len(batch)
                    continue
                all_clusters.extend(described.get("clusters", []))

            if not all_clusters and failed_lookups:
                return None
            return {"clusters": all_clusters, "failed_lookups": failed_lookups}

        except Exception:
            return None

    @staticmethod
    def _container_insights_enabled(configuration_values):
        """Whether the CloudWatch Observability add-on config leaves Container
        Insights on. Enhanced (Classic) Container Insights is on by default;
        it is off only when ``containerInsights.enabled`` is false and OTel
        Container Insights (off by default) is not enabled instead.
        Non-JSON (YAML) configuration is treated as defaults.
        """
        if not configuration_values:
            return True
        try:
            config = json.loads(configuration_values)
        except ValueError:
            return True
        if not isinstance(config, dict):
            return True

        def enabled(key, default):
            section = config.get(key)
            if isinstance(section, dict) and "enabled" in section:
                return section["enabled"] is True
            return default

        return enabled("containerInsights", True) or enabled(
            "otelContainerInsights", False
        )

    def execute_eks_addons_check(self):
        """Custom check for EKS observability add-ons across all EKS clusters"""
        try:
            # First get all EKS clusters
            clusters_result = self.run_aws_command(
                "aws eks list-clusters --output json"
            )
            if clusters_result is None:
                return None
            if "clusters" not in clusters_result:
                return {"total_clusters": 0, "observability_clusters": 0}

            cluster_names = clusters_result["clusters"]
            observability_clusters = []
            # Add-on installed but not ACTIVE, or Container Insights turned off.
            degraded_clusters = []
            failed_clusters = []

            # Check for observability add-on in each cluster
            for cluster_name in cluster_names:
                try:
                    addons_result = self.run_aws_command(
                        f"aws eks list-addons --cluster-name {self._sanitize(cluster_name)} --output json"
                    )
                    if addons_result is None:
                        failed_clusters.append(cluster_name)
                        continue
                    if "amazon-cloudwatch-observability" not in addons_result.get(
                        "addons", []
                    ):
                        continue
                    addon_result = self.run_aws_command(
                        f"aws eks describe-addon --cluster-name {self._sanitize(cluster_name)} --addon-name amazon-cloudwatch-observability --output json"
                    )
                    if addon_result is None or "addon" not in addon_result:
                        failed_clusters.append(cluster_name)
                        continue
                    addon = addon_result["addon"]
                    status = addon.get("status", "UNKNOWN")
                    insights_enabled = self._container_insights_enabled(
                        addon.get("configurationValues", "")
                    )
                    if status == "ACTIVE" and insights_enabled:
                        observability_clusters.append(cluster_name)
                    else:
                        degraded_clusters.append(
                            {
                                "cluster": cluster_name,
                                "status": status,
                                "container_insights_enabled": insights_enabled,
                            }
                        )
                except Exception:
                    failed_clusters.append(cluster_name)

            if cluster_names and len(failed_clusters) == len(cluster_names):
                return None

            # Unreadable clusters are excluded from the denominator.
            return {
                "total_clusters": len(cluster_names) - len(failed_clusters),
                "failed_lookups": len(failed_clusters),
                "observability_clusters": len(observability_clusters),
                "clusters_with_observability": observability_clusters,
                "clusters_with_addon_issues": degraded_clusters,
            }

        except Exception:
            return None

    def execute_lambda_insights_check(self):
        """Custom check for Lambda functions with Lambda Insights enabled"""
        try:
            # Get all Lambda functions
            functions_result = self.run_aws_command(
                "aws lambda list-functions --output json"
            )
            if functions_result is None:
                return None
            if "Functions" not in functions_result:
                return {"total_functions": 0, "insights_functions": 0}

            functions = functions_result["Functions"]
            insights_functions = []

            # Check each function for Lambda Insights layer
            for func in functions:
                func_name = func.get("FunctionName", "")
                layers = func.get("Layers", [])

                # Check if any layer contains LambdaInsightsExtension
                for layer in layers:
                    layer_arn = layer.get("Arn", "")
                    if "LambdaInsightsExtension" in layer_arn:
                        insights_functions.append(func_name)
                        break

            return {
                "total_functions": len(functions),
                "insights_functions": len(insights_functions),
                "functions_with_insights": insights_functions,
            }

        except Exception:
            return None
