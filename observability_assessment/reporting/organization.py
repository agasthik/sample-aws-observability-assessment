# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Organization assessment HTML report."""

import html as html_mod
from datetime import datetime
from pathlib import Path

from .cloudscape_bridge import CATEGORIES, inline_report


def organization_payload(results):
    """Build the organization data contract consumed by the report frontend."""
    assessed_count = len(results.account_results)
    failed_count = len(results.failed_accounts)
    scored_count = sum(
        any(question.assessed for question in result.assessment_checks)
        for result in results.account_results.values()
    )
    accounts = []

    for account_id, result in sorted(results.account_results.items()):
        has_score = any(question.assessed for question in result.assessment_checks)
        unavailable = sum(check.status == "error" for check in result.discovery_checks)
        not_assessed = sum(
            not question.assessed for question in result.assessment_checks
        )
        partial = sum(
            question.assessed
            and bool(question.unavailable_check_ids or question.incomplete_check_ids)
            for question in result.assessment_checks
        )
        accounts.append(
            {
                "id": account_id,
                "name": results.account_names.get(account_id) or "",
                "score": result.overall_score if has_score else None,
                "maturity": (
                    result.maturity_level or "Not assessed"
                    if has_score
                    else "Not assessed"
                ),
                "status": (
                    "partial" if unavailable or not_assessed or partial else "success"
                ),
                "error": None,
                "link": (
                    f"observability_assessment_{result.timestamp}_{account_id}.html"
                ),
                "unavailableChecks": unavailable,
                "notAssessedQuestions": not_assessed,
                "partialQuestions": partial,
            }
        )

    for account_id, error in sorted(results.failed_accounts.items()):
        accounts.append(
            {
                "id": account_id,
                "name": results.account_names.get(account_id) or "",
                "score": None,
                "maturity": None,
                "status": "failed",
                "error": error,
                "link": None,
                "unavailableChecks": None,
                "notAssessedQuestions": None,
                "partialQuestions": None,
            }
        )

    return {
        "reportType": "organization",
        "meta": {
            "organizationId": results.organization_id,
            "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        },
        "summary": {
            "averageScore": results.overall_score_avg,
            "minScore": results.overall_score_min,
            "maxScore": results.overall_score_max,
            "maturityLevel": results.maturity_level if scored_count else "Not assessed",
            "bestMaturityLevel": (
                results.best_maturity_level if scored_count else "Not assessed"
            ),
            "assessedAccounts": assessed_count,
            "scoredAccounts": scored_count,
            "totalAccounts": assessed_count + failed_count,
            "failedAccounts": failed_count,
        },
        "categories": [
            {
                "id": category_id,
                "label": label,
                "score": results.category_scores_avg.get(source_category),
                "min": results.category_scores_min.get(source_category),
                "max": results.category_scores_max.get(source_category),
            }
            for category_id, label, source_category in CATEGORIES
        ],
        "accounts": accounts,
    }


def _fallback_html(payload):
    """Keep essential results and report links available without JavaScript."""
    summary = payload["summary"]
    average = summary["averageScore"]
    average_display = f"{average:.1f}/4.0" if average is not None else "N/A"
    account_items = []
    for account in payload["accounts"]:
        label = account["id"]
        if account["name"]:
            label += f" - {account['name']}"
        label = html_mod.escape(label)
        if account["link"]:
            link = html_mod.escape(account["link"], quote=True)
            account_items.append(f'<li><a href="{link}">{label}</a></li>')
        else:
            error = html_mod.escape(str(account["error"] or "Unknown error"))
            account_items.append(f"<li>{label}: Failed — {error}</li>")

    return (
        "<main>"
        "<h1>Organization Observability Assessment Summary</h1>"
        f"<p>Accounts assessed: {summary['assessedAccounts']}/{summary['totalAccounts']}</p>"
        f"<p>Average score: {average_display}</p>"
        "<h2>Account reports</h2><ul>" + "".join(account_items) + "</ul></main>"
    )


class OrganizationReportMixin:
    """Render the summary for a multi-account assessment."""

    def generate_summary_report(self):
        """Generate a standalone Cloudscape organization summary report."""
        payload = organization_payload(self.org_results)
        html = inline_report(
            payload,
            title="Organization Observability Assessment Summary",
            fallback=_fallback_html(payload),
        )
        report_path = Path("assessment-result") / self.summary_report_filename
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(html, encoding="utf-8")
        print(f"Organization summary report: {report_path}")
