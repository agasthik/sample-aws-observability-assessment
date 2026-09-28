# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Python tool (`observability_assessment_comprehensive.py`, ~10,000 lines) that evaluates AWS observability maturity. It runs 50 AWS CLI discovery checks across 5 categories (Logs, Metrics, Traces, Dashboards & Alerting, Organization), scores 17 questions on a 1.0–4.0 maturity scale, and emits an HTML report (with a radar chart) plus a CSV. Nearly all checks are read-only (`describe`/`list`/`get`); the one exception is the EC2 CloudWatch agent check, which uses `ssm:SendCommand` to run a read-only diagnostic on SSM-managed instances (see Conventions & gotchas). Two CloudFormation templates deploy it to run unattended in CodeBuild.

## Commands

```bash
# Run locally against a profile/region
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --region us-west-2

# Run a single discovery check by ID (fast iteration on one check)
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --single-check 7

# Run all discovery checks for one question (1-17) and score just that question
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --single-question 3

# Assume a role first (this is how CodeBuild invokes it)
python3 observability_assessment_comprehensive.py --role-arn arn:aws:iam::ACCT:role/service-role/ObservabilityAssessmentRole --region us-west-2

# Verbose diagnostics (per-instance details, failed-command output)
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --debug
```

There is no build step or behavioral test suite. Pull-request CI runs Ruff checks for changed Python files, CloudFormation linting for template changes, and ASH security scanning. Requires Python 3.12+ (the CodeBuild buildspec selects Python 3.12 on the `amazonlinux-x86_64-standard:6.0` image). `requirements.txt` declares an unbounded minimum `boto3>=1.34.0`; AWS CLI v2.34.21 or later must also be on PATH (the tool shells out to `aws`, and the AWS DevOps Agent check requires the `devops-agent` commands introduced in that version). The AWS CLI is not a pip package. Output is written to `assessment-result/` (gitignored). Use `--single-check` / `--single-question` to validate changes rather than running the full 50-check pass, which is slow and hits many AWS APIs. Pass `--debug` for verbose per-instance and failed-command logging.

## Architecture

The runtime is concentrated in `observability_assessment_comprehensive.py` and split between two orchestration classes:

- `ComprehensiveObservabilityAssessment` assesses one account.
- `MultiAccountAssessment` discovers and assesses multiple accounts, aggregates their results, and generates an organization summary.

The single-account flow is `ComprehensiveObservabilityAssessment.run_full_assessment()`:

1. `sts get-caller-identity` to resolve account ID (names the output files).
2. `setup_discovery_checks()` — registers all discovery checks via `add_discovery_check(name, category, command)`, which assigns sequential IDs and de-duplicates by (name, command), merging categories.
3. `execute_all_discovery_checks()` → `execute_discovery_check(id)` for each.
4. `setup_assessment_questions()` — defines the 17 `ObservabilityCheck` questions with their 4 maturity-level descriptions.
5. `assess_all_categories()` → `assess_logs_maturity()`, `assess_metrics_maturity()`, etc. Each maps discovery-check results to a `current_level` (1–4) per question.
6. `generate_html_report()` — builds the HTML + radar chart from the scored results.

The multi-account flow is `MultiAccountAssessment.run()`:

1. Discover accounts from an explicit list or recursively from AWS Organizations root/OU IDs.
2. Assess accounts concurrently with a `ThreadPoolExecutor`.
3. Assume `/service-role/ObservabilityAssessmentRole` in each target account and run the single-account flow. The caller account can fall back to its existing credentials if assuming its local assessment role is denied.
4. Record failed accounts separately, aggregate scores from successful accounts, and generate a timestamped organization summary.

### Four data classes

- `DiscoveryCheck` — one AWS probe: `id`, `name`, `category`, `command`, `result`, `status`, `evidence`.
- `ObservabilityCheck` — one of the 17 scored questions; holds `current_level`, `evidence_check_ids`, `explanation`, and `maturity_descriptions`.
- `AssessmentResults` — the aggregate (lists of both, category scores, overall score).
- `OrganizationAssessmentResults` — successful and failed account results plus aggregate average/minimum/maximum scores and summary-report metadata.

### How a discovery check runs

`execute_discovery_check()` dispatches on `check.command`:

- Known custom command strings are matched through explicit `if`/`elif` branches (for example, `custom_ec2_cloudwatch_agent_check` → `execute_ec2_cloudwatch_agent_check()`). A `custom_` prefix alone does not trigger custom dispatch; every new custom check needs an explicit branch.
- Otherwise `command` is a literal AWS CLI string, run through `run_aws_command()`.

`run_aws_command()` is the single choke point for all CLI calls: it injects `--profile`/`--region`, retries on throttling with exponential backoff, parses stdout as JSON, and uses `shell=False` + `shlex.split()` by default (only falling back to `shell=True` when the command contains shell metacharacters). When interpolating any dynamic value into a command, run it through `_sanitize()` (`shlex.quote`).

### Adding a new discovery check

1. Register it in `setup_discovery_checks()` with `add_discovery_check(...)`.
2. If it's non-trivial, add a `custom_...` branch in `execute_discovery_check()` and an `execute_..._check()` method.
3. Add the appropriate CSV-export handling in `export_check_result_to_csv()`. Checks 12–50 currently fall through to a generic binary yes/no handler; extend that bound or add a dedicated branch when adding checks beyond 50.
4. Wire its result into the relevant `assess_*_maturity()` method — note these methods currently locate discovery checks **by their exact `name` string**, so name changes there are breaking.

### Scoring model
Each `assess_*_maturity()` method contains per-question `if question_id == N:` blocks with hardcoded level thresholds (e.g. "coverage >= 0.75 AND has_structured_json AND has_centralization" → level 4). Maturity is rule-based and deterministic — there is no ML in the scoring (see `AI_ML_SECURITY.md`). If you change what a check returns, the downstream threshold logic in these blocks likely needs updating too.

## Deployment (CloudFormation)

- `1-observability-assessment-role.yaml` — creates `ObservabilityAssessmentRole`, which is almost entirely read-only except for the scoped `ssm:SendCommand` permission used by the EC2 CloudWatch agent check. Deploy it in each target account for cross-account/multi-account mode.
- `2-observability-assessment-codebuild.yaml` — creates the report bucket, its access-log bucket, the CodeBuild project and role, and a Lambda-backed custom resource that triggers the first build. The buildspec updates AWS CLI v2, downloads the script from GitHub (falling back to the report bucket), runs the assessment, and uploads HTML, CSV, and a timestamped ZIP bundle.
- For single-account mode, set `CreateAssessmentRole=yes` (the default) and leave `AssessmentAccounts` and `AssessmentOUs` empty. CodeBuild invokes the tool with `--role-arn` for the role created in the same account.
- For multi-account mode, deploy template 1 to the target accounts, set `CreateAssessmentRole=no` in the central account, and provide either `AssessmentAccounts` or `AssessmentOUs`. `MultiAccountAssessment` assumes the target role separately in each account.

## Conventions & gotchas

- **Read-only by design.** Nearly every AWS interaction is `describe`/`list`/`get`, and the IAM policy in the role template grants read actions. The **one exception** is the EC2 CloudWatch agent check, which calls `ssm:SendCommand` (via the managed `AWS-RunShellScript` document) to run a read-only diagnostic on SSM-managed instances — it does not modify instances and is skipped for non-SSM-managed ones. Do not introduce any other mutating AWS call, and do not extend `SendCommand` usage to anything that changes state.
- `assessment-result/` is gitignored. The committed examples are `sample-result/observability_assessment_sample.html` and the scrubbed multi-account bundle under `sample-result/org-scan-sample/`.
- The target-account role template trusts the exact provided CodeBuild role. Local multi-account runs require a separately authorized principal in every target role trust policy.
- Most checks are scoped to the selected region and several use bounded samples. Read `ASSESSMENT_METHODOLOGY.md` before changing scope or scoring behavior.
- License is MIT-0; keep the `Copyright Amazon.com` / `SPDX-License-Identifier: MIT-0` header on source files.
- The `# nosec` / `# nosemgrep` comments on the subprocess calls are intentional (audited) — keep them when editing those lines.
