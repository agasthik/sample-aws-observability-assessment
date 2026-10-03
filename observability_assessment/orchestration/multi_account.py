# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import os
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

from ..assessment import ComprehensiveObservabilityAssessment
from ..models import OrganizationAssessmentResults, maturity_label
from ..reporting.organization import OrganizationReportMixin


class MultiAccountAssessment(OrganizationReportMixin):
    """Orchestrates observability assessment across multiple AWS accounts"""

    SUMMARY_FILENAME = "organization_summary.html"

    def __init__(
        self,
        profile=None,
        region="us-west-2",
        accounts=None,
        ou_ids=None,
        role_name="ObservabilityAssessmentRole",
        max_workers=5,
    ):
        self.profile = profile
        self.region = region
        self.explicit_accounts = accounts
        self.ou_ids = ou_ids
        self.role_name = role_name
        self.max_workers = max(1, max_workers)
        self.management_account_id = None
        self.discovered_accounts = []
        self.account_names = {}
        run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Timestamp the org summary filename so repeated scans (multi-region or
        # re-runs) don't overwrite each other. Derived once from the single
        # per-run timestamp and reused for the file itself and for the
        # "Back to Organization Summary" back-link embedded in every per-account
        # report, so cross-report navigation stays consistent.
        base, ext = os.path.splitext(self.SUMMARY_FILENAME)
        self.summary_report_filename = f"{base}_{run_timestamp}{ext}"
        self.org_results = OrganizationAssessmentResults(
            summary_report_filename=self.summary_report_filename,
            timestamp=run_timestamp,
        )
        # Resolve management account
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        self.management_account_id = sts.get_caller_identity()["Account"]
        self.org_results.management_account_id = self.management_account_id

    def discover_accounts(self):
        """Discover accounts to assess. Populates discovered_accounts and account_names."""
        if self.explicit_accounts:
            valid = []
            for acct in self.explicit_accounts:
                acct = acct.strip()
                if len(acct) == 12 and acct.isdigit():
                    valid.append(acct)
                else:
                    print(f"[WARN] Skipping invalid account ID: {acct}")
            if not valid:
                print("[ERROR] No valid account IDs provided")
                sys.exit(1)
            self.discovered_accounts = list(dict.fromkeys(valid))
            self._resolve_account_names(self.discovered_accounts)
            return

        session_kwargs = {"region_name": self.region}
        if self.profile:
            session_kwargs["profile_name"] = self.profile
        session = boto3.Session(**session_kwargs)

        try:
            org_client = session.client("organizations")
            if self.ou_ids:
                accounts = []
                for ou_id in self.ou_ids:
                    accounts.extend(
                        self._list_accounts_recursive(org_client, ou_id.strip())
                    )
            else:
                accounts = []
                paginator = org_client.get_paginator("list_accounts")
                for page in paginator.paginate():
                    for acct in page["Accounts"]:
                        if acct["Status"] == "ACTIVE":
                            accounts.append(acct)
                try:
                    org_info = org_client.describe_organization()["Organization"]
                    self.org_results.organization_id = org_info.get("Id", "")
                except Exception:
                    pass

            # Deduplicate by account ID
            seen = set()
            unique = []
            for acct in accounts:
                if acct["Id"] not in seen:
                    seen.add(acct["Id"])
                    unique.append(acct)
            accounts = unique

            for acct in accounts:
                self.account_names[acct["Id"]] = acct.get("Name")
            ids = [a["Id"] for a in accounts]
            self.discovered_accounts = list(dict.fromkeys(ids))

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AWSOrganizationsNotInUseException"):
                print(
                    f"[ERROR] Cannot discover accounts via Organizations ({code}). Provide --accounts explicitly."
                )
                sys.exit(1)
            raise

        if not self.discovered_accounts:
            print("[ERROR] No accounts found to assess.")
            sys.exit(1)

    @staticmethod
    def _list_accounts_recursive(org_client, parent_id):
        """Recursively list all active accounts under an OU (including nested OUs)."""
        accounts = []
        # A failed page can hide accounts or whole OU subtrees. Stop rather
        # than producing an incomplete organization summary.
        try:
            paginator = org_client.get_paginator("list_accounts_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for acct in page["Accounts"]:
                    if acct["Status"] == "ACTIVE":
                        accounts.append(acct)
        except Exception as e:
            raise RuntimeError(f"Failed to list accounts under {parent_id}: {e}") from e
        try:
            paginator = org_client.get_paginator("list_organizational_units_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page["OrganizationalUnits"]:
                    accounts.extend(
                        MultiAccountAssessment._list_accounts_recursive(
                            org_client, ou["Id"]
                        )
                    )
        except Exception as e:
            raise RuntimeError(
                f"Failed to list child OUs under {parent_id}: {e}"
            ) from e
        return accounts

    def _resolve_account_names(self, account_ids):
        """Best-effort resolution of account names via Organizations API."""
        session_kwargs = {"region_name": self.region}
        if self.profile:
            session_kwargs["profile_name"] = self.profile
        session = boto3.Session(**session_kwargs)
        try:
            org_client = session.client("organizations")
            for aid in account_ids:
                if aid not in self.account_names:
                    try:
                        info = org_client.describe_account(AccountId=aid)["Account"]
                        self.account_names[aid] = info.get("Name")
                    except Exception:
                        self.account_names[aid] = None
        except Exception:
            for aid in account_ids:
                self.account_names.setdefault(aid, None)

    def assess_account(self, account_id):
        """Assess a single account. Returns (account_id, AssessmentResults|None, error|None)."""
        role_arn = f"arn:aws:iam::{account_id}:role/service-role/{self.role_name}"
        try:
            try:
                assessment = ComprehensiveObservabilityAssessment(
                    profile=self.profile,
                    region=self.region,
                    role_arn=role_arn,
                    summary_report_filename=self.summary_report_filename,
                )
            except ClientError as e:
                # Every account — including the caller/management account — must run
                # under the assessment role, which carries the discovery permissions
                # the running identity may lack (e.g. the limited CodeBuild role that
                # only has Logs/S3/STS/Organizations access). If assuming the role is
                # denied for the caller account — typically a local run whose profile
                # already has the permissions but is not trusted by the role — fall
                # back to the caller's own credentials. Non-caller accounts have no
                # usable fallback, so surface the error for them.
                if account_id != self.management_account_id:
                    raise
                print(
                    f"  [WARN] {account_id}: could not assume {role_arn} ({e}); "
                    "falling back to the caller's own credentials. Checks those "
                    "credentials cannot run will be reported as unavailable."
                )
                assessment = ComprehensiveObservabilityAssessment(
                    profile=self.profile,
                    region=self.region,
                    role_arn=None,
                    summary_report_filename=self.summary_report_filename,
                )
            if not assessment.run_full_assessment():
                return (account_id, None, "Could not get AWS identity")
            return (account_id, assessment.results, None)
        except Exception as e:
            return (account_id, None, str(e))

    def calculate_aggregated_scores(self):
        """Compute avg/min/max scores across accounts with assessed questions."""
        results = self.org_results
        scored_results = [
            account
            for account in results.account_results.values()
            if any(question.assessed for question in account.assessment_checks)
        ]
        if not scored_results:
            results.maturity_level = "Not assessed"
            results.best_maturity_level = "Not assessed"
            return
        all_cats = set()
        for ar in scored_results:
            all_cats.update(ar.category_scores.keys())

        for cat in all_cats:
            cat_scores = [
                ar.category_scores[cat]
                for ar in scored_results
                if cat in ar.category_scores
            ]
            if cat_scores:
                results.category_scores_avg[cat] = sum(cat_scores) / len(cat_scores)
                results.category_scores_min[cat] = min(cat_scores)
                results.category_scores_max[cat] = max(cat_scores)

        overall = [ar.overall_score for ar in scored_results]
        if overall:
            results.overall_score_avg = sum(overall) / len(overall)
            results.overall_score_min = min(overall)
            results.overall_score_max = max(overall)

        results.maturity_level = maturity_label(results.overall_score_avg)
        results.best_maturity_level = maturity_label(results.overall_score_max)

    def run(self):
        """Run multi-account assessment end-to-end."""
        import concurrent.futures

        print("Starting Multi-Account Observability Assessment")
        print("=" * 80)

        self.discover_accounts()
        total = len(self.discovered_accounts)
        print(f"Accounts to assess: {total}")
        for aid in self.discovered_accounts:
            name = self.account_names.get(aid) or ""
            tag = " (management)" if aid == self.management_account_id else ""
            display = f"  • {aid} - {name}{tag}" if name else f"  • {aid}{tag}"
            print(display)
        print("=" * 80)

        completed = 0
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            futures = {
                executor.submit(self.assess_account, aid): aid
                for aid in self.discovered_accounts
            }
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                aid, result, error = future.result()
                name = self.account_names.get(aid) or ""
                display = f"{aid} - {name}" if name else aid
                if result:
                    self.org_results.account_results[aid] = result
                    print(
                        f"  [{completed}/{total}] [OK] {display} — {result.maturity_level} "
                        f"({result.overall_score:.1f})"
                        if result.overall_score is not None
                        else f"  [{completed}/{total}] [OK] {display} — Not assessed (N/A)"
                    )
                else:
                    self.org_results.failed_accounts[aid] = error or "Unknown error"
                    print(f"  [{completed}/{total}] [ERROR] {display} — {error}")

        self.org_results.account_names = self.account_names
        self.calculate_aggregated_scores()
        self.generate_summary_report()

        print("=" * 80)
        r = self.org_results
        print("[OK] Organization assessment complete!")
        average_display = (
            f"{r.overall_score_avg:.1f}" if r.overall_score_avg is not None else "N/A"
        )
        best_display = (
            f"{r.overall_score_max:.1f}" if r.overall_score_max is not None else "N/A"
        )
        print(
            f"Organization Maturity: {r.maturity_level} ({average_display}) — Best Account: {r.best_maturity_level} ({best_display})"
        )
        print(
            f"Accounts: {len(r.account_results)} succeeded, {len(r.failed_accounts)} failed"
        )
