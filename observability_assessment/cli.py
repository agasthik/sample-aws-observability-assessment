# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import argparse
import logging
import sys

from .assessment import ComprehensiveObservabilityAssessment
from .orchestration import MultiAccountAssessment


def main():
    parser = argparse.ArgumentParser(
        description="AWS Comprehensive Observability Assessment"
    )
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument("--region", default="us-west-2", help="AWS region")
    parser.add_argument(
        "--role-arn", help="IAM role ARN to assume before running checks"
    )
    parser.add_argument(
        "--single-check",
        type=int,
        help="Run only a specific check by ID (outputs to console)",
    )
    parser.add_argument(
        "--single-question",
        type=int,
        help="Run only discovery checks for a specific question (1-17) and score it",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--accounts", help="Comma-separated account IDs for multi-account assessment"
    )
    parser.add_argument(
        "--ou", help="Comma-separated organization root or OU IDs to scope assessment"
    )
    parser.add_argument(
        "--cross-account-role",
        default="ObservabilityAssessmentRole",
        help="Role name to assume in target accounts (default: ObservabilityAssessmentRole)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=5,
        help="Max parallel account assessments (default: 5)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    multi_account = args.accounts or args.ou

    if multi_account and (
        args.single_check is not None or args.single_question is not None
    ):
        print(
            "[ERROR] --single-check and --single-question are not supported in multi-account mode."
        )
        sys.exit(1)
    if multi_account and args.role_arn:
        print(
            "[ERROR] Use --cross-account-role instead of --role-arn for multi-account mode."
        )
        sys.exit(1)

    if multi_account:
        accounts_list = (
            [a.strip() for a in args.accounts.split(",")] if args.accounts else None
        )
        ou_list = [o.strip() for o in args.ou.split(",")] if args.ou else None
        ma = MultiAccountAssessment(
            profile=args.profile,
            region=args.region,
            accounts=accounts_list,
            ou_ids=ou_list,
            role_name=args.cross_account_role,
            max_workers=args.max_workers,
        )
        ma.run()
    else:
        assessment = ComprehensiveObservabilityAssessment(
            profile=args.profile, region=args.region, role_arn=args.role_arn
        )
        if args.single_check is not None:
            succeeded = assessment.run_single_check(args.single_check)
        elif args.single_question is not None:
            succeeded = assessment.run_single_question(args.single_question)
        else:
            succeeded = assessment.run_assessment()
        if not succeeded:
            sys.exit(1)
