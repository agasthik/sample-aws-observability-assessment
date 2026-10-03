# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0


class OrganizationDiscoveryMixin:
    """Collect organization-level observability signals."""

    def execute_devops_agent_spaces_check(self):
        """Check for AWS DevOps Agent Spaces in current region and us-east-1"""
        try:
            all_spaces = []
            regions_checked = []
            regions_failed = []

            # Always check us-east-1
            regions_to_check = ["us-east-1"]

            # Add current region if it's not us-east-1
            if self.region != "us-east-1":
                regions_to_check.append(self.region)

            for region in regions_to_check:
                try:
                    # Execute the AWS DevOps Agent command. The devops-agent
                    # service commands ship natively in AWS CLI v2 (>= 2.34.21),
                    # so no custom endpoint or service model is required.
                    command = f"aws devops-agent list-agent-spaces --region {region} --output json"
                    result = self.run_aws_command(command)
                    if result is None:
                        regions_failed.append(region)
                        continue

                    agent_spaces = result.get("agentSpaces", [])

                    for space in agent_spaces:
                        all_spaces.append(
                            {
                                "name": space.get("name", "Unknown"),
                                "agentSpaceId": space.get("agentSpaceId", "Unknown"),
                                "createdAt": space.get("createdAt", "Unknown"),
                                "updatedAt": space.get("updatedAt", "Unknown"),
                                "region": region,
                            }
                        )

                    regions_checked.append(region)

                except Exception:
                    # Continue checking other regions if one fails
                    regions_failed.append(region)

            if not regions_checked:
                return None

            return {
                "total_spaces": len(all_spaces),
                "spaces_details": all_spaces,
                "regions_checked": regions_checked,
                "regions_failed": regions_failed,
                "failed_lookups": len(regions_failed),
            }

        except Exception:
            return None

    @staticmethod
    def _omni_scope(arn):
        """Classify a CloudWatch Omni domain ARN as organization- or account-scoped."""
        return "Organization" if ":organization-domain/" in (arn or "") else "Account"

    def execute_cloudwatch_omni_spaces_check(self):
        """Check for CloudWatch Omni domains and spaces in the selected region.

        Uses only account-level list APIs, which need IAM permissions but no
        space access grant. Returns None when spaces cannot be listed (for
        example, missing permissions or Omni unavailable in the region) so the
        check is reported as not evaluated rather than as "not adopted".
        """
        spaces_result = self.run_aws_command(
            "aws cloudwatchomni list-spaces --output json"
        )
        if spaces_result is None:
            return None
        domains_result = self.run_aws_command(
            "aws cloudwatchomni list-domains --output json"
        )

        domains = [
            {
                "name": domain.get("name", "Unknown"),
                "domainId": domain.get("domainId", "Unknown"),
                "scope": self._omni_scope(domain.get("domainArn")),
                "status": domain.get("status", "Unknown"),
                "identityCenter": bool(domain.get("identityCenterInstanceArn")),
            }
            for domain in (domains_result or {}).get("items", [])
        ]
        spaces = [
            {
                "name": space.get("name", "Unknown"),
                "spaceId": space.get("spaceId", "Unknown"),
                "status": space.get("status", "Unknown"),
                "scope": (
                    self._omni_scope(space.get("domainArn"))
                    if space.get("domainArn")
                    else "None"
                ),
                "createdAt": space.get("createdAt", "Unknown"),
            }
            for space in spaces_result.get("items", [])
        ]
        active_spaces = [s for s in spaces if s["status"] == "ACTIVE"]

        return {
            "total_spaces": len(spaces),
            "active_spaces": len(active_spaces),
            "spaces_details": spaces,
            "total_domains": len(domains),
            "domains_details": domains,
            "domains_listed": domains_result is not None,
            "has_organization_domain": any(
                s["scope"] == "Organization" for s in active_spaces
            ),
            "region": self.region,
        }

    def execute_cloudwatch_omni_integrations_check(self):
        """Check CloudWatch Omni integrations (Context Graph, Slack, external agents).

        Returns None when integrations cannot be listed so the check is
        reported as not evaluated.
        """
        result = self.run_aws_command(
            "aws cloudwatchomni list-integrations --output json"
        )
        if result is None:
            return None

        integrations = [
            {
                "name": item.get("name", "Unknown"),
                "type": item.get("integrationType", "Unknown"),
                "status": item.get("status", "Unknown"),
                "scope": item.get("scope", "Unknown"),
            }
            for item in result.get("items", [])
            if item.get("status") != "DELETED"
        ]
        active = [i for i in integrations if i["status"] == "ACTIVE"]
        active_by_type = {}
        for integration in active:
            active_by_type[integration["type"]] = (
                active_by_type.get(integration["type"], 0) + 1
            )

        return {
            "total_integrations": len(integrations),
            "active_integrations": len(active),
            "active_by_type": active_by_type,
            "has_context_graph": bool(
                active_by_type.get("AWS_INTEGRATION")
                or active_by_type.get("AWS_CONFIG_SLREC")
            ),
            "integrations_details": integrations,
            "region": self.region,
        }
