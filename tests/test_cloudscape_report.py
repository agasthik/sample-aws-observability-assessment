# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Behavioral contracts for the self-contained Cloudscape assessment report."""

import contextlib
import io
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import unquote
from xml.etree import ElementTree

from observability_assessment.models import (
    DiscoveryCheck,
    ObservabilityCheck,
    OrganizationAssessmentResults,
)
from observability_assessment.reporting.organization import OrganizationReportMixin
from observability_assessment_comprehensive import ComprehensiveObservabilityAssessment
from test_characterization import temporary_working_directory


class ReportDocument(HTMLParser):
    def __init__(self):
        super().__init__()
        self.data_islands = []
        self.inline_scripts = 0
        self.inline_styles = 0
        self.remote_runtime_assets = []
        self.favicons = []
        self.event_handler_attributes = []
        self._script = None
        self._style = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.event_handler_attributes.extend(
            name for name, _ in attrs if name.startswith("on")
        )
        if tag == "script":
            if attributes.get("src"):
                self.remote_runtime_assets.append(attributes["src"])
            self._script = [attributes, []]
        elif tag == "style":
            self._style = True
        elif tag == "link" and "stylesheet" in attributes.get("rel", "").split():
            self.remote_runtime_assets.append(attributes.get("href"))
        elif tag == "link" and "icon" in attributes.get("rel", "").split():
            self.favicons.append(attributes)

    def handle_data(self, data):
        if self._script is not None:
            self._script[1].append(data)
        elif self._style and data.strip():
            self.inline_styles += 1

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            attributes, parts = self._script
            if attributes.get("id") == "assessment-data":
                self.data_islands.append((attributes, "".join(parts)))
            elif "".join(parts).strip():
                self.inline_scripts += 1
            self._script = None
        elif tag == "style":
            self._style = False


def sample_assessment(evidence="Healthy evidence"):
    assessment = ComprehensiveObservabilityAssessment(
        region="us-east-1",
        summary_report_filename="organization_summary.html",
    )
    assessment.results.account_id = "111111111111"
    assessment.html_file = "assessment-result/cloudscape.html"
    assessment.results.discovery_checks = [
        DiscoveryCheck(
            1,
            "Log coverage",
            "Logs",
            "aws logs describe-log-groups",
            status="success",
            evidence=evidence,
        ),
        DiscoveryCheck(
            2,
            "Log retention",
            "Logs",
            "aws logs describe-log-groups",
            status="error",
            evidence="Access denied",
        ),
        DiscoveryCheck(
            3,
            "Metric coverage",
            "Metrics",
            "aws cloudwatch list-metrics",
            result={"failed_lookups": 1},
            status="success",
            evidence="One metric lookup failed",
        ),
        DiscoveryCheck(
            4,
            "Trace coverage",
            "Traces",
            "aws xray get-service-graph",
            status="error",
            evidence="Access denied",
        ),
    ]
    descriptions = {level: f"Description for level {level}" for level in range(1, 5)}
    assessment.results.assessment_checks = [
        ObservabilityCheck(
            1,
            "Logs",
            "How complete is log coverage?",
            current_level=3,
            assessed=True,
            evidence_check_ids=[1, 2],
            explanation="Some log sources were assessed.",
            maturity_descriptions=descriptions,
            unavailable_check_ids=[2],
        ),
        ObservabilityCheck(
            2,
            "Metrics",
            "How complete is metric coverage?",
            current_level=1,
            assessed=True,
            evidence_check_ids=[3],
            explanation="One lookup failed.",
            maturity_descriptions=descriptions,
            incomplete_check_ids=[3],
        ),
        ObservabilityCheck(
            3,
            "Traces",
            "How complete is trace coverage?",
            current_level=4,
            evidence_check_ids=[4],
            explanation="Not assessed: discovery failed.",
            maturity_descriptions=descriptions,
            assessed=False,
            unavailable_check_ids=[4],
        ),
    ]
    assessment.results.category_scores = {"Logs": 3.0, "Metrics": 1.0}
    assessment.get_recommendations = Mock(
        return_value=[
            (
                "Review coverage",
                "Check the remaining sources.",
                "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/",
            )
        ]
    )
    return assessment


def render_report(assessment):
    with temporary_working_directory():
        with contextlib.redirect_stdout(io.StringIO()):
            assessment.generate_html_report()
        saved_file = Path(assessment.html_file)
        if not saved_file.is_file():
            raise AssertionError(f"Report was not saved at {saved_file}")
        html = saved_file.read_text(encoding="utf-8")
        document = ReportDocument()
        document.feed(html)
        if len(document.data_islands) != 1:
            raise AssertionError("Report must contain one assessment data island")
        attributes, raw_data = document.data_islands[0]
        return html, document, attributes, json.loads(raw_data)


class CloudscapeReportTests(unittest.TestCase):
    def test_account_and_organization_reports_embed_the_same_valid_favicon(self):
        _, account_document, _, _ = render_report(sample_assessment())

        organization = OrganizationReportMixin()
        organization.org_results = OrganizationAssessmentResults()
        organization.summary_report_filename = "organization_summary.html"
        with temporary_working_directory():
            with contextlib.redirect_stdout(io.StringIO()):
                organization.generate_summary_report()
            organization_html = Path(
                "assessment-result/organization_summary.html"
            ).read_text(encoding="utf-8")

        organization_document = ReportDocument()
        organization_document.feed(organization_html)
        for document in (account_document, organization_document):
            self.assertEqual(len(document.favicons), 1)
            icon = document.favicons[0]
            self.assertEqual(icon["type"], "image/svg+xml")
            self.assertEqual(icon["sizes"], "any")
            self.assertTrue(icon["href"].startswith("data:image/svg+xml,"))
            svg = unquote(icon["href"].removeprefix("data:image/svg+xml,"))
            self.assertEqual(
                ElementTree.fromstring(svg).tag,
                "{http://www.w3.org/2000/svg}svg",
            )
        self.assertEqual(
            account_document.favicons[0]["href"],
            organization_document.favicons[0]["href"],
        )

    def test_saved_report_exposes_scores_and_assessment_data(self):
        assessment = sample_assessment()

        html, _, attributes, data = render_report(assessment)

        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertEqual(attributes.get("type"), "application/json")
        self.assertEqual(data["meta"]["accountId"], "111111111111")
        self.assertEqual(data["meta"]["region"], "us-east-1")
        self.assertEqual(data["meta"]["backLink"], "organization_summary.html")
        self.assertTrue(data["meta"]["generatedAt"])
        self.assertEqual(assessment.results.timestamp, assessment.timestamp)
        self.assertEqual(assessment.results.overall_score, 2.0)
        self.assertEqual(assessment.results.maturity_level, "Proactive")

        summary = data["summary"]
        self.assertEqual(summary["overallScore"], 2.0)
        self.assertEqual(summary["maturityLevel"], "Proactive")
        self.assertEqual(
            (
                summary["discoveryEvaluated"],
                summary["discoveryTotal"],
                summary["discoveryUnavailable"],
            ),
            (2, 4, 2),
        )
        self.assertEqual(
            (
                summary["questionsAssessed"],
                summary["questionsTotal"],
                summary["partialQuestions"],
            ),
            (2, 3, 2),
        )

        categories = {category["label"]: category for category in data["categories"]}
        self.assertEqual(
            (
                categories["Logs"]["score"],
                categories["Logs"]["assessedCount"],
                categories["Logs"]["totalCount"],
            ),
            (3.0, 1, 1),
        )
        self.assertEqual(
            (
                categories["Metrics"]["score"],
                categories["Metrics"]["assessedCount"],
                categories["Metrics"]["totalCount"],
            ),
            (1.0, 1, 1),
        )
        self.assertIsNone(categories["Traces"]["score"])
        self.assertEqual(categories["Traces"]["assessedCount"], 0)
        self.assertEqual(categories["Traces"]["totalCount"], 1)
        self.assertTrue(all(category["id"] for category in data["categories"]))

    def test_partial_unavailable_and_not_assessed_remain_distinct(self):
        _, _, _, data = render_report(sample_assessment())

        questions = {question["id"]: question for question in data["questions"]}
        self.assertEqual(set(questions), {1, 2, 3})
        self.assertTrue(questions[1]["assessed"])
        self.assertEqual(questions[1]["level"], 3)
        self.assertEqual(questions[1]["evidenceCheckIds"], [1, 2])
        self.assertEqual(questions[1]["unavailableCheckIds"], [2])
        self.assertEqual(questions[1]["incompleteCheckIds"], [])
        self.assertEqual(questions[1]["question"], "How complete is log coverage?")
        self.assertEqual(questions[1]["explanation"], "Some log sources were assessed.")
        self.assertEqual(
            questions[1]["maturityDescriptions"][0],
            {"level": 1, "description": "Description for level 1"},
        )
        self.assertEqual(
            questions[1]["recommendations"][0],
            {
                "title": "Review coverage",
                "description": "Check the remaining sources.",
                "url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/",
            },
        )

        self.assertTrue(questions[2]["assessed"])
        self.assertEqual(questions[2]["unavailableCheckIds"], [])
        self.assertEqual(questions[2]["incompleteCheckIds"], [3])
        self.assertFalse(questions[3]["assessed"])
        self.assertIsNone(questions[3]["level"])
        self.assertEqual(questions[3]["levelLabel"], "Not assessed")
        self.assertEqual(questions[3]["unavailableCheckIds"], [4])
        self.assertEqual(questions[3]["recommendations"], [])

        discovery = {check["id"]: check for check in data["discovery"]}
        self.assertEqual(set(discovery), {1, 2, 3, 4})
        self.assertEqual(discovery[2]["status"], "error")
        self.assertEqual(discovery[2]["evidenceText"], "Access denied")
        self.assertEqual(discovery[3]["status"], "success")
        self.assertEqual(discovery[3]["command"], "aws cloudwatch list-metrics")
        self.assertEqual(discovery[3]["name"], "Metric coverage")
        self.assertEqual(discovery[3]["category"], "Metrics")

    def test_hostile_evidence_cannot_break_out_of_embedded_json(self):
        hostile = (
            "Evidence </script><img src=x onerror=alert(1)> & <strong>raw</strong>"
        )

        html, document, _, data = render_report(sample_assessment(hostile))

        self.assertIn("Evidence", data["discovery"][0]["evidenceText"])
        self.assertIn("raw", data["discovery"][0]["evidenceText"])
        self.assertNotIn("</script><img", html.lower())
        self.assertNotIn("<img src=x onerror=", html.lower())
        self.assertNotIn("onerror", document.event_handler_attributes)
        self.assertGreater(document.inline_scripts, 0)
        self.assertGreater(document.inline_styles, 0)
        self.assertEqual(document.remote_runtime_assets, [])

    def test_discovery_evidence_separates_summary_and_resource_details(self):
        evidence = (
            "Total: 3 log groups | Vended: 2 | Custom: 1"
            "<details><summary>Show Details</summary><div>"
            "<strong>AWS Vended/Service Logs:</strong><br>"
            "• /aws/lambda/example-a<br>• /aws/lambda/example-b<br><br>"
            "<strong>Custom Application Logs:</strong><br>"
            "• /application/example</div></details>"
        )

        _, _, _, data = render_report(sample_assessment(evidence))

        check = data["discovery"][0]
        self.assertEqual(
            check["evidenceSummary"], "Total: 3 log groups | Vended: 2 | Custom: 1"
        )
        self.assertIn(
            "AWS Vended/Service Logs:\n• /aws/lambda/example-a\n"
            "• /aws/lambda/example-b",
            check["evidenceDetails"],
        )
        self.assertIn(
            "Custom Application Logs:\n• /application/example", check["evidenceDetails"]
        )
        self.assertNotIn("Show Details", check["evidenceText"])
        self.assertEqual(data["discovery"][1]["evidenceSummary"], "Access denied")
        self.assertEqual(data["discovery"][1]["evidenceDetails"], "")

    def test_detail_text_stays_in_embedded_data(self):
        evidence = (
            "Found 1 item<details><summary>Show Details</summary>"
            "<div>Resource: &lt;example&gt;<br>"
            "• </script><img src=x onerror=alert(1)> escaped</div></details>"
        )

        html, document, _, data = render_report(sample_assessment(evidence))

        self.assertIn("Resource: <example>", data["discovery"][0]["evidenceDetails"])
        self.assertIn("escaped", data["discovery"][0]["evidenceDetails"])
        self.assertNotIn("</script><img", html.lower())
        self.assertNotIn("<img src=x onerror=", html.lower())
        self.assertNotIn("onerror", document.event_handler_attributes)


if __name__ == "__main__":
    unittest.main()
