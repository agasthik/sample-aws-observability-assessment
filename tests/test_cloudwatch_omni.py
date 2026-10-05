# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Contracts for the CloudWatch Omni discovery checks and their scoring."""

import unittest

from test_characterization import configured_assessment, discovery, question

OMNI_SPACES_ID = 51
OMNI_INTEGRATIONS_ID = 52
DASHBOARDS_ID = 33

ACCOUNT_DOMAIN = "arn:aws:cloudwatch:us-west-2:111111111111:domain/d-account"
ORG_DOMAIN = "arn:aws:cloudwatch:us-west-2:111111111111:organization-domain/d-org"


def responder(responses):
    """Return a run_aws_command stub that answers by CLI subcommand."""

    def run(command, *_args, **_kwargs):
        for subcommand, response in responses.items():
            if f"cloudwatchomni {subcommand} " in command:
                return response
        return {}

    return run


def omni_spaces_result(active_spaces=1, organization=False):
    return {
        "total_spaces": active_spaces,
        "active_spaces": active_spaces,
        "spaces_details": [],
        "total_domains": 1,
        "domains_details": [],
        "domains_listed": True,
        "has_organization_domain": organization,
        "region": "us-west-2",
    }


class OmniSpacesDiscoveryTests(unittest.TestCase):
    def test_unlistable_spaces_are_not_evaluated(self):
        assessment = configured_assessment()
        assessment.run_aws_command = responder({"list-spaces": None})

        self.assertIsNone(assessment.execute_cloudwatch_omni_spaces_check())

    def test_counts_active_spaces_and_detects_organization_domain(self):
        assessment = configured_assessment()
        assessment.run_aws_command = responder(
            {
                "list-spaces": {
                    "items": [
                        {
                            "spaceId": "s-1",
                            "name": "prod",
                            "status": "ACTIVE",
                            "domainArn": ORG_DOMAIN,
                        },
                        {
                            "spaceId": "s-2",
                            "name": "old",
                            "status": "SUSPENDED",
                            "domainArn": ORG_DOMAIN,
                        },
                    ]
                },
                "list-domains": {
                    "items": [
                        {
                            "domainId": "d-org",
                            "name": "example",
                            "domainArn": ORG_DOMAIN,
                            "status": "ACTIVE",
                        }
                    ]
                },
            }
        )

        result = assessment.execute_cloudwatch_omni_spaces_check()

        self.assertEqual((result["total_spaces"], result["active_spaces"]), (2, 1))
        self.assertTrue(result["has_organization_domain"])
        self.assertEqual(result["domains_details"][0]["scope"], "Organization")
        self.assertEqual(result["spaces_details"][0]["scope"], "Organization")

    def test_account_domain_without_domain_listing_still_reports_spaces(self):
        assessment = configured_assessment()
        assessment.run_aws_command = responder(
            {
                "list-spaces": {
                    "items": [
                        {
                            "spaceId": "s-1",
                            "name": "dev",
                            "status": "ACTIVE",
                            "domainArn": ACCOUNT_DOMAIN,
                        }
                    ]
                },
                "list-domains": None,
            }
        )

        result = assessment.execute_cloudwatch_omni_spaces_check()

        self.assertEqual(result["active_spaces"], 1)
        self.assertFalse(result["has_organization_domain"])
        self.assertFalse(result["domains_listed"])

    def test_account_space_does_not_inherit_separate_organization_domain(self):
        assessment = configured_assessment()
        assessment.run_aws_command = responder(
            {
                "list-spaces": {
                    "items": [
                        {
                            "spaceId": "s-account",
                            "name": "account-space",
                            "status": "ACTIVE",
                            "domainArn": ACCOUNT_DOMAIN,
                        }
                    ]
                },
                "list-domains": {
                    "items": [
                        {
                            "domainId": "d-org",
                            "name": "unused-org-domain",
                            "domainArn": ORG_DOMAIN,
                            "status": "ACTIVE",
                        }
                    ]
                },
            }
        )

        result = assessment.execute_cloudwatch_omni_spaces_check()

        self.assertEqual(result["active_spaces"], 1)
        self.assertEqual(result["spaces_details"][0]["scope"], "Account")
        self.assertEqual(result["domains_details"][0]["scope"], "Organization")
        self.assertFalse(result["has_organization_domain"])

        target = question(assessment, 16)
        assessment.results.assessment_checks = [target]
        discovery(assessment, DASHBOARDS_ID).result = {
            "DashboardEntries": [{"DashboardName": "ops"}]
        }
        discovery(assessment, OMNI_SPACES_ID).result = result
        assessment.assess_organization_maturity()

        self.assertEqual(target.current_level, 1)
        self.assertNotIn("CloudWatch Omni organization domain", target.explanation)


class OmniIntegrationsDiscoveryTests(unittest.TestCase):
    def test_unlistable_integrations_are_not_evaluated(self):
        assessment = configured_assessment()
        assessment.run_aws_command = responder({"list-integrations": None})

        self.assertIsNone(assessment.execute_cloudwatch_omni_integrations_check())

    def test_excludes_deleted_and_detects_context_graph(self):
        assessment = configured_assessment()
        assessment.run_aws_command = responder(
            {
                "list-integrations": {
                    "items": [
                        {
                            "name": "graph",
                            "integrationType": "AWS_INTEGRATION",
                            "status": "ACTIVE",
                            "scope": "ACCOUNT",
                        },
                        {
                            "name": "chat",
                            "integrationType": "SLACK",
                            "status": "PENDING_OAUTH",
                            "scope": "ACCOUNT",
                        },
                        {
                            "name": "gone",
                            "integrationType": "SLACK",
                            "status": "DELETED",
                            "scope": "ACCOUNT",
                        },
                    ]
                }
            }
        )

        result = assessment.execute_cloudwatch_omni_integrations_check()

        self.assertEqual(
            (result["total_integrations"], result["active_integrations"]), (2, 1)
        )
        self.assertEqual(result["active_by_type"], {"AWS_INTEGRATION": 1})
        self.assertTrue(result["has_context_graph"])


class OmniEvidenceTests(unittest.TestCase):
    def test_evidence_escapes_space_names(self):
        assessment = configured_assessment()
        check = discovery(assessment, OMNI_SPACES_ID)
        check.result = omni_spaces_result()
        check.result["spaces_details"] = [
            {
                "name": "<script>",
                "spaceId": "s-1",
                "status": "ACTIVE",
                "scope": "Account",
                "createdAt": "now",
            }
        ]

        evidence = assessment.generate_detailed_evidence(check)

        self.assertIn("Found 1 active of 1 CloudWatch Omni spaces", evidence)
        self.assertIn("&lt;script&gt;", evidence)
        self.assertNotIn("<script>", evidence)


class OmniScoringTests(unittest.TestCase):
    def assess(self, question_id, assess_method, omni_result):
        assessment = configured_assessment()
        target = question(assessment, question_id)
        assessment.results.assessment_checks = [target]
        discovery(assessment, DASHBOARDS_ID).result = {
            "DashboardEntries": [{"DashboardName": "ops"}]
        }
        discovery(assessment, OMNI_SPACES_ID).result = omni_result
        getattr(assessment, assess_method)()
        return target

    def test_active_space_counts_as_unified_log_and_metric_access(self):
        for question_id, method in (
            (3, "assess_logs_maturity"),
            (7, "assess_metrics_maturity"),
        ):
            with self.subTest(question_id=question_id):
                without = self.assess(question_id, method, None)
                with_omni = self.assess(question_id, method, omni_spaces_result())

                self.assertEqual(without.current_level, 1)
                self.assertEqual(with_omni.current_level, 2)
                self.assertIn(OMNI_SPACES_ID, with_omni.evidence_check_ids)
                self.assertIn("CloudWatch Omni unified access", with_omni.explanation)

    def test_suspended_only_spaces_do_not_count(self):
        target = self.assess(
            3, "assess_logs_maturity", omni_spaces_result(active_spaces=0)
        )

        self.assertEqual(target.current_level, 1)

    def test_organization_domain_is_an_enterprise_strategy_signal(self):
        org = self.assess(
            16, "assess_organization_maturity", omni_spaces_result(organization=True)
        )
        account = self.assess(
            16, "assess_organization_maturity", omni_spaces_result(organization=False)
        )

        self.assertIn("CloudWatch Omni organization domain", org.explanation)
        self.assertNotIn("CloudWatch Omni organization domain", account.explanation)
        self.assertIn(OMNI_SPACES_ID, org.evidence_check_ids)
        self.assertIn(OMNI_INTEGRATIONS_ID, org.evidence_check_ids)


if __name__ == "__main__":
    unittest.main()
