# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0


from observability_assessment.text import plural


class LogsDiscoveryMixin:
    """Collect CloudWatch Logs coverage and configuration."""

    def get_largest_log_groups_by_compute_type(self):
        """Get 10 largest log groups for each compute type (EC2, ECS, Lambda, EKS).

        Returns None when the log groups cannot be listed, so dependent checks
        report "error" instead of an empty (and misleading) 0/0 result.
        """
        try:
            log_groups_result = self.run_aws_command(
                "aws logs describe-log-groups --output json"
            )
            if log_groups_result is None:
                return None
            if "logGroups" not in log_groups_result:
                return {"EC2": [], "ECS": [], "Lambda": [], "EKS": []}

            all_log_groups = log_groups_result["logGroups"]

            # Categorize log groups by compute type
            compute_groups = {"EC2": [], "ECS": [], "Lambda": [], "EKS": []}

            for lg in all_log_groups:
                group_name = lg.get("logGroupName", "")
                size_bytes = lg.get("storedBytes", 0)

                if "/aws/lambda/" in group_name:
                    compute_groups["Lambda"].append((group_name, size_bytes))
                elif (
                    "/aws/ecs/" in group_name
                    or (
                        "/aws/containerinsights/" in group_name
                        and "ecs" in group_name.lower()
                    )
                    or "/ecs/" in group_name
                    or "ecs" in group_name.lower()
                ):
                    compute_groups["ECS"].append((group_name, size_bytes))
                elif "/aws/eks/" in group_name or (
                    "/aws/containerinsights/" in group_name
                    and "eks" in group_name.lower()
                ):
                    compute_groups["EKS"].append((group_name, size_bytes))
                elif "/aws/ec2/" in group_name or any(
                    keyword in group_name.lower()
                    for keyword in ["ec2", "instance", "server"]
                ):
                    compute_groups["EC2"].append((group_name, size_bytes))

            # Get top 10 largest for each compute type
            largest_groups = {}
            for compute_type, groups in compute_groups.items():
                # Sort by size (descending) and take top 10
                sorted_groups = sorted(groups, key=lambda x: x[1], reverse=True)[:10]
                largest_groups[compute_type] = [
                    group[0] for group in sorted_groups
                ]  # Just the names

            return largest_groups

        except Exception:
            return None

    def execute_field_indexes_per_log_group_check(self):
        """Custom check for field indexes on top 20 largest log groups by size"""
        try:
            # Get all log groups and sort by size
            log_groups_result = self.run_aws_command(
                "aws logs describe-log-groups --output json"
            )
            if log_groups_result is None:
                return None
            if "logGroups" not in log_groups_result:
                return {
                    "total_log_groups": 0,
                    "indexed_log_groups": 0,
                    "sample_indexed_groups": [],
                    "field_index_details": [],
                }

            all_log_groups = log_groups_result["logGroups"]

            # Sort by size and get top 20, excluding system-generated log groups
            # Filter out Lambda Insights, Container Insights, and Application Signals log groups
            filtered_groups = []
            for lg in all_log_groups:
                log_group_name = lg.get("logGroupName", "")
                # Skip system-generated log groups
                if (
                    log_group_name.startswith("/aws/lambda-insights")
                    or log_group_name.startswith("/aws/containerinsights/")
                    or log_group_name.startswith("/aws/application-signals/")
                ):
                    continue
                filtered_groups.append(lg)

            sorted_groups = sorted(
                filtered_groups, key=lambda x: x.get("storedBytes", 0), reverse=True
            )[:20]
            target_log_groups = [lg.get("logGroupName", "") for lg in sorted_groups]

            if not target_log_groups:
                return {
                    "total_log_groups": 0,
                    "indexed_log_groups": 0,
                    "sample_indexed_groups": [],
                    "field_index_details": [],
                }

            indexed_groups = []
            field_index_details = []
            failed_groups = []

            # Check each target log group for field indexes
            for log_group_name in target_log_groups:
                try:
                    # Check for field indexes on this log group
                    escaped_name = self._sanitize(log_group_name)
                    index_result = self.run_aws_command(
                        f"aws logs describe-field-indexes --log-group-identifiers {escaped_name} --output json"
                    )
                    if index_result is None:
                        failed_groups.append(log_group_name)
                        continue
                    if index_result.get("fieldIndexes"):
                        # Filter out default/system field indexes (those starting with @)
                        custom_indexes = [
                            fi
                            for fi in index_result["fieldIndexes"]
                            if not fi.get("fieldIndexName", "").startswith("@")
                        ]

                        if (
                            custom_indexes
                        ):  # Only count if there are custom field indexes
                            indexed_groups.append(log_group_name)
                            # Collect custom field index names only
                            field_names = [
                                fi.get("fieldIndexName", "Unknown")
                                for fi in custom_indexes
                            ]
                            field_index_details.append(
                                {
                                    "log_group": log_group_name,
                                    "field_names": field_names,
                                }
                            )
                except Exception:
                    failed_groups.append(log_group_name)

            if len(failed_groups) == len(target_log_groups):
                return None

            # Unreadable groups are excluded from the denominator.
            return {
                "total_log_groups": len(target_log_groups) - len(failed_groups),
                "indexed_log_groups": len(indexed_groups),
                "sample_indexed_groups": indexed_groups,
                "field_index_details": field_index_details,
                "failed_lookups": len(failed_groups),
            }

        except Exception:
            return None

    def execute_log_export_tasks_per_log_group_check(self):
        """Custom check for log export task history across ALL log groups"""
        try:
            # Step 1: Get all log groups
            log_groups_result = self.run_aws_command(
                "aws logs describe-log-groups --output json"
            )
            if log_groups_result is None:
                return None
            if "logGroups" not in log_groups_result:
                return {
                    "total_log_groups": 0,
                    "exported_log_groups": 0,
                    "sample_exported_groups": [],
                }

            log_groups = log_groups_result["logGroups"]
            total_groups = len(log_groups)
            exported_groups = []

            # Step 2: Get all export tasks (current and historical)
            export_tasks_result = self.run_aws_command(
                "aws logs describe-export-tasks --output json"
            )
            if export_tasks_result is None:
                return None
            if "exportTasks" not in export_tasks_result:
                return {
                    "total_log_groups": total_groups,
                    "exported_log_groups": 0,
                    "sample_exported_groups": [],
                }

            export_tasks = export_tasks_result["exportTasks"]

            # Step 3: Create set of log groups that have had export tasks
            exported_log_group_names = set()
            for task in export_tasks:
                log_group_name = task.get("logGroupName", "")
                if log_group_name:
                    exported_log_group_names.add(log_group_name)

            # Step 4: Check which of our log groups have export history
            for log_group in log_groups:
                log_group_name = log_group.get("logGroupName", "")
                if log_group_name in exported_log_group_names:
                    exported_groups.append(log_group_name)

            return {
                "total_log_groups": total_groups,
                "exported_log_groups": len(exported_groups),
                "sample_exported_groups": exported_groups,
            }

        except Exception:
            return None

    def execute_top_log_groups_retention_check(self):
        """Custom check for retention policies on the top 10 largest log groups"""
        try:
            # Step 1: Get all log groups with their sizes
            log_groups_result = self.run_aws_command(
                "aws logs describe-log-groups --output json"
            )
            if log_groups_result is None:
                return None
            if "logGroups" not in log_groups_result:
                return {
                    "top_log_groups": [],
                    "groups_with_retention": 0,
                    "total_size_gb": 0,
                }

            log_groups = log_groups_result["logGroups"]

            # Step 2: Sort by storedBytes (largest first) and take top 10
            sorted_groups = sorted(
                log_groups, key=lambda x: x.get("storedBytes", 0), reverse=True
            )
            top_10_groups = sorted_groups[:10]

            # Step 3: Analyze retention policies for top 10
            groups_with_retention = 0
            total_size_bytes = 0
            top_groups_info = []

            for group in top_10_groups:
                name = group.get("logGroupName", "Unknown")
                size_bytes = group.get("storedBytes", 0)
                retention_days = group.get("retentionInDays")

                total_size_bytes += size_bytes

                if retention_days is not None:
                    groups_with_retention += 1

                top_groups_info.append(
                    {
                        "name": name,
                        "size_bytes": size_bytes,
                        "size_mb": round(size_bytes / 1048576, 1),
                        "retention_days": retention_days,
                    }
                )

            total_size_gb = round(total_size_bytes / 1073741824, 1)

            # Export to CSV
            self.export_check_to_csv(
                check_name="Log Groups Retention Policies",
                found_count=groups_with_retention,
                total_count=len(top_10_groups),
                details={
                    "with_retention": groups_with_retention,
                    "without_retention": len(top_10_groups) - groups_with_retention,
                },
            )

            return {
                "top_log_groups": top_groups_info,
                "groups_with_retention": groups_with_retention,
                "total_size_gb": total_size_gb,
            }

        except Exception:
            return None

    def execute_subscription_filters_coverage_check(self):
        """Custom check for subscription filter coverage across top log groups"""
        try:
            # Use the pre-identified largest log groups instead of all log groups.
            # None means they could not be listed, so this check cannot run.
            if self.largest_log_groups is None:
                return None
            if not self.largest_log_groups:
                return {
                    "total_log_groups": 0,
                    "groups_with_subscription_filters": 0,
                    "sample_filtered_groups": [],
                }

            # Flatten the largest log groups from all compute types
            top_log_groups = []
            for compute_type, groups in self.largest_log_groups.items():
                top_log_groups.extend(groups)

            filtered_groups = []
            failed_groups = []

            # Check only the top log groups for subscription filters
            for log_group_name in top_log_groups:
                try:
                    # Check for subscription filters on this log group
                    escaped_name = self._sanitize(log_group_name)
                    filters_result = self.run_aws_command(
                        f"aws logs describe-subscription-filters --log-group-name {escaped_name} --output json"
                    )
                    if filters_result is None:
                        failed_groups.append(log_group_name)
                    elif filters_result.get("subscriptionFilters"):
                        filtered_groups.append(log_group_name)
                except Exception:
                    failed_groups.append(log_group_name)

            if top_log_groups and len(failed_groups) == len(top_log_groups):
                return None

            # Unreadable groups are excluded from the denominator.
            return {
                "total_log_groups": len(top_log_groups) - len(failed_groups),
                "groups_with_subscription_filters": len(filtered_groups),
                "sample_filtered_groups": filtered_groups,
                "failed_lookups": len(failed_groups),
            }

        except Exception:
            return None

    def execute_log_centralization_analysis_check(self):
        """Comprehensive check for log centralization patterns"""
        try:
            patterns = []
            account_type = "Standalone"
            org_status = "Not in Organization"
            # Probes whose AWS calls failed. Their absence from ``patterns``
            # means "unknown", not "not configured".
            probes_failed = []

            # 1. Check AWS Organizations status (for context only)
            org_result = self.run_aws_command(
                "aws organizations describe-organization --output json"
            )
            # describe-organization also succeeds in member accounts, so the
            # management account is identified by MasterAccountId.
            if org_result and "Organization" in org_result:
                management_id = org_result["Organization"].get("MasterAccountId")
                if management_id and management_id == self.results.account_id:
                    org_status = "Organization Management Account"
                else:
                    org_status = "Organization Member Account"
            elif org_result is None and "AWSOrganizationsNotInUseException" not in (
                getattr(self, "last_aws_error", "") or ""
            ):
                org_status = "Unknown"

            # 2. Check for CloudWatch Logs Centralization Rules (native centralization) using CLI.
            # Only management/delegated-admin accounts can list these, so a
            # failure is expected elsewhere and is not counted in probes_failed.
            try:
                centralization_rules = self.run_aws_command(
                    "aws observabilityadmin list-centralization-rules-for-organization --all-regions --output json"
                )
                if centralization_rules and centralization_rules.get(
                    "CentralizationRuleSummaries"
                ):
                    rules = centralization_rules["CentralizationRuleSummaries"]
                    rule_count = len(rules)
                    healthy_rules = len(
                        [r for r in rules if r.get("RuleHealth") == "Healthy"]
                    )
                    patterns.append(
                        f"CloudWatch Logs Centralization Rules ({plural(rule_count, 'rule')}, {healthy_rules} healthy)"
                    )
            except Exception:
                pass

            # 3. Check for CloudWatch Observability Access Manager
            try:
                oam_sinks = self.run_aws_command("aws oam list-sinks --output json")
                oam_links = self.run_aws_command("aws oam list-links --output json")
                if oam_sinks is None or oam_links is None:
                    probes_failed.append("Observability Access Manager")

                if oam_sinks and oam_sinks.get("Items"):
                    patterns.append(
                        "Observability Access Manager Sink (Central Monitoring)"
                    )

                if oam_links and oam_links.get("Items"):
                    patterns.append(
                        "Observability Access Manager Link (Source Account)"
                    )
            except Exception:
                probes_failed.append("Observability Access Manager")

            # 4. Check for cross-account subscription filters
            try:
                log_groups_result = self.run_aws_command(
                    "aws logs describe-log-groups --output json"
                )
                cross_account_filters = 0
                unreadable_groups = 0
                if log_groups_result is None:
                    probes_failed.append("Cross-account subscription filters")
                for log_group in (log_groups_result or {}).get("logGroups", []):
                    log_group_name = log_group.get("logGroupName")
                    if not log_group_name:
                        continue
                    sub_filters = self.run_aws_command(
                        "aws logs describe-subscription-filters "
                        f"--log-group-name {self._sanitize(log_group_name)} "
                        "--output json"
                    )
                    if sub_filters is None:
                        unreadable_groups += 1
                        continue
                    for filter_item in sub_filters.get("subscriptionFilters", []):
                        dest_arn = filter_item.get("destinationArn", "")
                        arn_parts = dest_arn.split(":")
                        if len(arn_parts) > 4 and arn_parts[4] not in (
                            "",
                            self.results.account_id,
                        ):
                            cross_account_filters += 1

                if cross_account_filters > 0:
                    patterns.append(
                        f"Cross-account subscription filters ({plural(cross_account_filters, 'filter')})"
                    )
                if unreadable_groups:
                    probes_failed.append(
                        f"Subscription filters ({plural(unreadable_groups, 'log group')} unreadable)"
                    )
            except Exception:
                probes_failed.append("Cross-account subscription filters")

            # 5. Check for Kinesis/Firehose destinations
            try:
                kinesis_streams = self.run_aws_command(
                    "aws kinesis list-streams --output json"
                )
                if kinesis_streams is None:
                    probes_failed.append("Kinesis Data Streams")
                if kinesis_streams and kinesis_streams.get("StreamNames"):
                    stream_count = len(kinesis_streams["StreamNames"])
                    patterns.append(
                        f"Kinesis Data Streams ({plural(stream_count, 'stream')})"
                    )

                # list-delivery-streams has no CLI paginator and returns 10
                # names by default, so page with ExclusiveStartDeliveryStreamName.
                firehose_streams = {"DeliveryStreamNames": []}
                start_arg = ""
                while True:
                    page = self.run_aws_command(
                        f"aws firehose list-delivery-streams --limit 10000{start_arg} --output json"
                    )
                    if page is None:
                        firehose_streams = None
                        break
                    names = page.get("DeliveryStreamNames", [])
                    firehose_streams["DeliveryStreamNames"].extend(names)
                    if not page.get("HasMoreDeliveryStreams") or not names:
                        break
                    start_arg = f" --exclusive-start-delivery-stream-name {self._sanitize(names[-1])}"
                if firehose_streams is None:
                    probes_failed.append("Amazon Data Firehose")
                if firehose_streams and firehose_streams.get("DeliveryStreamNames"):
                    firehose_details = []
                    for stream_name in firehose_streams["DeliveryStreamNames"]:
                        stream_desc = self.run_aws_command(
                            f"aws firehose describe-delivery-stream --delivery-stream-name {self._sanitize(stream_name)} --output json"
                        )
                        if stream_desc is None:
                            probes_failed.append(f"Firehose stream {stream_name}")
                        if stream_desc and stream_desc.get("DeliveryStreamDescription"):
                            desc = stream_desc["DeliveryStreamDescription"]
                            destinations = desc.get("Destinations", [])
                            if destinations:
                                dest = destinations[0]
                                if "S3DestinationDescription" in dest:
                                    bucket_arn = dest["S3DestinationDescription"].get(
                                        "BucketARN", "Unknown"
                                    )
                                    bucket_name = (
                                        bucket_arn.split(":::")[-1]
                                        if ":::" in bucket_arn
                                        else bucket_arn
                                    )
                                    firehose_details.append(
                                        f"{stream_name} → S3 bucket {bucket_name} (same account)"
                                    )
                                elif "ExtendedS3DestinationDescription" in dest:
                                    bucket_arn = dest[
                                        "ExtendedS3DestinationDescription"
                                    ].get("BucketARN", "Unknown")
                                    bucket_name = (
                                        bucket_arn.split(":::")[-1]
                                        if ":::" in bucket_arn
                                        else bucket_arn
                                    )
                                    firehose_details.append(
                                        f"{stream_name} → S3 bucket {bucket_name} (same account)"
                                    )
                                else:
                                    firehose_details.append(
                                        f"{stream_name} → Unknown destination"
                                    )

                    if firehose_details:
                        patterns.append(
                            f"Amazon Data Firehose: {', '.join(firehose_details)}"
                        )
            except Exception:
                probes_failed.append("Kinesis/Firehose")

            # 6. Check for centralized S3 buckets with log-like naming
            # Removed - keyword-based detection is not reliable

            # 7. Check for log destination policies (cross-account)
            try:
                destinations = self.run_aws_command(
                    "aws logs describe-destinations --output json"
                )
                if destinations is None:
                    probes_failed.append("CloudWatch Logs Destinations")
                if destinations and destinations.get("destinations"):
                    dest_count = len(destinations["destinations"])
                    patterns.append(
                        f"CloudWatch Logs Destinations ({plural(dest_count, 'destination')})"
                    )
            except Exception:
                probes_failed.append("CloudWatch Logs Destinations")

            # Nothing found and nothing could be checked: not evaluable.
            all_probes_failed = {
                "Observability Access Manager",
                "Cross-account subscription filters",
                "Kinesis Data Streams",
                "Amazon Data Firehose",
                "CloudWatch Logs Destinations",
            }.issubset(probes_failed)
            if not patterns and all_probes_failed:
                return None

            # Determine account type based on actual configurations
            if not patterns:
                account_type = "No Centralization Detected"

            return {
                "centralization_patterns": patterns,
                "account_type": account_type,
                "organization_status": org_status,
                "probes_failed": probes_failed,
                "failed_lookups": len(probes_failed),
            }

        except Exception:
            return None

    def execute_oam_links_and_sinks_check(self):
        """Check both OAM links and sinks to determine account type and centralization setup"""
        try:
            # Check for OAM links (source account perspective)
            links_result = self.run_aws_command("aws oam list-links --output json")

            # Check for OAM sinks (monitoring account perspective)
            sinks_result = self.run_aws_command("aws oam list-sinks --output json")

            # The account type depends on both answers, so either failing
            # makes the check unevaluable.
            if links_result is None or sinks_result is None:
                return None
            links = links_result.get("Items", [])
            sinks = sinks_result.get("Items", [])

            # Determine account type and configuration
            account_type = "Unknown"
            configuration_details = []

            if links and sinks:
                account_type = "Hybrid Account (Both Links and Sinks)"
                configuration_details.append(
                    f"{plural(len(links), 'OAM link')} configured"
                )
                configuration_details.append(
                    f"{plural(len(sinks), 'OAM sink')} configured"
                )
            elif links and not sinks:
                account_type = "Source Account (Has Links)"
                configuration_details.append(
                    f"{plural(len(links), 'OAM link')} sending data to monitoring accounts"
                )
                # Add link details
                for link in links[:3]:
                    sink_arn = link.get("SinkArn", "Unknown")
                    link_id = link.get("Id", "Unknown")
                    configuration_details.append(f"Link {link_id} → {sink_arn}")
            elif sinks and not links:
                account_type = "Monitoring Account (Has Sinks)"
                configuration_details.append(
                    f"{plural(len(sinks), 'OAM sink')} receiving data from source accounts"
                )
                # Add sink details
                for sink in sinks[:3]:
                    sink_name = sink.get("Name", "Unknown")
                    sink_arn = sink.get("Arn", "Unknown")
                    configuration_details.append(f"Sink {sink_name}: {sink_arn}")
            else:
                account_type = "No OAM Configuration"
                configuration_details.append("No OAM links or sinks found")

            return {
                "account_type": account_type,
                "links_count": len(links),
                "sinks_count": len(sinks),
                "links": links,
                "sinks": sinks,
                "configuration_details": configuration_details,
            }

        except Exception:
            return None

    def execute_json_structured_logs_check(self):
        """Check for JSON structured logs by examining field indexes (fast method)"""
        try:
            if self.largest_log_groups is None:
                return None
            if not self.largest_log_groups:
                return {
                    "total_groups_checked": 0,
                    "json_groups": 0,
                    "sample_groups": [],
                }

            # Combine all largest log groups
            all_target_groups = []
            for compute_type, groups in self.largest_log_groups.items():
                all_target_groups.extend(groups)

            if not all_target_groups:
                return {
                    "total_groups_checked": 0,
                    "json_groups": 0,
                    "sample_groups": [],
                }

            json_groups = []
            failed_groups = []

            # Check each log group for field indexes (indicates JSON structured logs)
            for group_name in all_target_groups:
                try:
                    # Check if log group has field indexes (indicates structured JSON logs)
                    result = self.run_aws_command(
                        "aws logs describe-field-indexes "
                        f"--log-group-identifiers {self._sanitize(group_name)} "
                        "--output json"
                    )

                    if result is None:
                        failed_groups.append(group_name)
                        continue
                    if result.get("fieldIndexes"):
                        # Filter out default @timestamp and @message indexes
                        custom_indexes = [
                            idx
                            for idx in result["fieldIndexes"]
                            if idx.get("fieldIndexName")
                            not in ["@timestamp", "@message"]
                        ]
                        if custom_indexes:
                            json_groups.append(group_name)

                except Exception:
                    failed_groups.append(group_name)

            if len(failed_groups) == len(all_target_groups):
                return None

            # Unreadable groups are excluded from the denominator.
            return {
                "total_groups_checked": len(all_target_groups) - len(failed_groups),
                "json_groups": len(json_groups),
                "sample_groups": json_groups[:5],  # Show first 5 as examples
                "failed_lookups": len(failed_groups),
            }

        except Exception:
            return None

    def execute_log_group_tags_check(self):
        """Check how many log groups have resource tags for retention governance"""
        try:
            result = self.run_aws_command(
                "aws resourcegroupstaggingapi get-resources --resource-type-filters logs:log-group --output json"
            )
            if result is None:
                return None
            if "ResourceTagMappingList" not in result:
                return {"total_tagged_log_groups": 0, "tagged_log_groups": []}

            resources = result["ResourceTagMappingList"]
            tagged = []
            for r in resources:
                arn = r.get("ResourceARN", "")
                name = (
                    arn.split(":log-group:")[-1].rstrip(":*")
                    if ":log-group:" in arn
                    else arn
                )
                tags = {t["Key"]: t["Value"] for t in r.get("Tags", [])}
                tagged.append({"name": name, "tags": tags})

            return {"total_tagged_log_groups": len(tagged), "tagged_log_groups": tagged}
        except Exception:
            return None

    def execute_stale_log_groups_check(self):
        """Check largest log groups for staleness using most recent log stream ingestion time."""
        import time

        try:
            if self.largest_log_groups is None:
                return None
            if not self.largest_log_groups:
                return {
                    "total_checked": 0,
                    "stale_log_groups": 0,
                    "active_log_groups": 0,
                    "stale_details": [],
                }
            # Flatten all largest log group names
            all_names = []
            for names in self.largest_log_groups.values():
                all_names.extend(names)
            if not all_names:
                return {
                    "total_checked": 0,
                    "stale_log_groups": 0,
                    "active_log_groups": 0,
                    "stale_details": [],
                }
            now_ms = int(time.time() * 1000)
            stale_details = []
            active_count = 0
            failed_groups = []
            for name in all_names:
                try:
                    resp = self.run_aws_command(
                        f"aws logs describe-log-streams --log-group-name {self._sanitize(name)} --order-by LastEventTime --descending --max-items 1 --output json"
                    )
                    # A failed lookup is unknown, not evidence of staleness.
                    if resp is None:
                        failed_groups.append(name)
                        continue
                    streams = resp.get("logStreams", [])
                    if not streams:
                        stale_details.append(
                            {
                                "name": name,
                                "days_since_ingestion": -1,
                                "reason": "no streams",
                            }
                        )
                        continue
                    last = streams[0].get("lastIngestionTime") or streams[0].get(
                        "lastEventTimestamp", 0
                    )
                    if last == 0:
                        stale_details.append(
                            {
                                "name": name,
                                "days_since_ingestion": -1,
                                "reason": "no ingestion time",
                            }
                        )
                    else:
                        days = (now_ms - last) / (1000 * 60 * 60 * 24)
                        if days > 90:
                            stale_details.append(
                                {
                                    "name": name,
                                    "days_since_ingestion": int(days),
                                    "reason": "stale",
                                }
                            )
                        else:
                            active_count += 1
                except Exception:
                    failed_groups.append(name)
            if len(failed_groups) == len(all_names):
                return None
            total_checked = len(all_names) - len(failed_groups)
            return {
                "total_checked": total_checked,
                "stale_log_groups": len(stale_details),
                "active_log_groups": active_count,
                "stale_percentage": round(len(stale_details) / total_checked * 100, 1),
                "stale_details": stale_details,
                "failed_lookups": len(failed_groups),
            }
        except Exception:
            return None

    def execute_log_groups_categorization_check(self):
        """Categorize log groups by source type: Vended/AWS Service Logs vs Custom Logs"""
        try:
            result = self.run_aws_command("aws logs describe-log-groups --output json")
            if result is None:
                return None

            log_groups = result.get("logGroups", [])
            vended_logs = []
            custom_logs = []

            # AWS vended log prefixes
            aws_prefixes = ["/aws/", "/aws-"]

            for lg in log_groups:
                name = lg.get("logGroupName", "")
                if any(name.startswith(prefix) for prefix in aws_prefixes):
                    vended_logs.append(name)
                else:
                    custom_logs.append(name)

            result_data = {
                "total_log_groups": len(log_groups),
                "vended_logs": vended_logs,
                "custom_logs": custom_logs,
                "vended_count": len(vended_logs),
                "custom_count": len(custom_logs),
            }

            # Export to CSV
            self.export_check_to_csv(
                check_name="Log Groups Categorization",
                found_count=len(vended_logs) + len(custom_logs),
                total_count=len(log_groups),
                details={
                    "Vended Logs": len(vended_logs),
                    "Custom Logs": len(custom_logs),
                },
            )

            return result_data

        except Exception:
            return None
