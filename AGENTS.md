# AGENTS.md

This file provides guidance to AI coding agents when working with code in this
repository.

## What this is

A modular Python tool with `observability_assessment_comprehensive.py` as its
command-line entry point. It runs 52 AWS discovery checks across 5 maturity
categories, scores 17 questions at levels 1–4 (overall score 1.0–4.0 when
assessed), and emits HTML and CSV
reports. Nearly all checks use read-only AWS calls. The EC2 CloudWatch agent
check uses `ssm:SendCommand` to run a read-only diagnostic on SSM-managed
instances. Two CloudFormation templates deploy the tool in CodeBuild.

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

There is no Python build step for running the assessment. The report UI is
compiled with Node.js 24, and its assets are committed so assessment runs do
not need Node.js. Pull-request CI runs the unittest suite on every PR and
rebuilds the report UI when its source or assets change. Ruff, CloudFormation
linting, and ASH security scanning run when their
respective changed-file filters match. The tool requires Python 3.12+,
`boto3`, and AWS CLI v2.37.0 or later on PATH (the `cloudwatchomni`
commands used by checks 51 and 52 first shipped in 2.37.0). The CodeBuild buildspec
selects Python 3.12 and installs the checked-out `requirements.txt`. Output
is written to `assessment-result/` (gitignored). Use `--single-check` or
`--single-question` for focused AWS validation, and `--debug` for verbose
diagnostics.

## Architecture

The runtime lives in `observability_assessment/`. The root script re-exports
the public classes and calls `observability_assessment.cli.main()`:

- `ComprehensiveObservabilityAssessment` assesses one account.
- `MultiAccountAssessment` discovers and assesses multiple accounts, aggregates their results, and generates an organization summary.

`models.py` holds result data classes; `aws.py` holds AWS CLI execution and
assumed-role handling; `discovery/` holds the check catalog, dispatch, and
service checks; `scoring/` holds question definitions and maturity rules;
`reporting/` holds CSV, evidence, recommendations, and HTML output;
`report_ui/` contains the Cloudscape React source; its compiled CSS and JS live
in `observability_assessment/reporting/assets/` and are embedded in generated
reports; `orchestration/` holds the multi-account runner.

The single-account flow is `ComprehensiveObservabilityAssessment.run_full_assessment()`:

1. `sts get-caller-identity` to resolve the account ID (used to name the output files).
2. `setup_discovery_checks()` samples the largest log groups, then loads 52
   fixed specifications from `discovery/check_specs.py`. Checks 1–50 preserve
   the former IDs and categories. Five commands and thirteen display names
   changed; see `ASSESSMENT_METHODOLOGY.md` for the migration list. Checks 51–52 are new.
3. `execute_all_discovery_checks()` → `execute_discovery_check(id)` for each.
4. `setup_assessment_questions()` — defines the 17 `ObservabilityCheck` questions with their 4 maturity-level descriptions.
5. `assess_all_categories()` → `assess_logs_maturity()`, `assess_metrics_maturity()`, etc. Each maps discovery-check results to a `current_level` (1–4) per question.
6. `generate_html_report()` — serializes scores and evidence, then embeds the
   Cloudscape UI assets and report data in a self-contained HTML file.

The multi-account flow is `MultiAccountAssessment.run()`:

1. Discover accounts from an explicit list or recursively from AWS Organizations root/OU IDs.
2. Assess accounts concurrently with a `ThreadPoolExecutor`.
3. Assume `/service-role/ObservabilityAssessmentRole` in each target account and run the single-account flow. The caller account can fall back to its existing credentials if assuming its local assessment role is denied.
4. Record failed accounts separately, aggregate scores from successful accounts, and generate a timestamped organization summary.

### Results and check specifications

- `CheckSpec` — an immutable built-in check definition with a stable key and
  ID, name, category, and command. `tests/discovery_catalog.json` freezes the
  current catalog, including new checks and renamed displays.
- `DiscoveryCheck` — one AWS probe: `id`, `name`, `category`, `command`, `result`, `status`, `evidence`.
- `ObservabilityCheck` — one of the 17 scored questions; holds `current_level`, `evidence_check_ids`, `explanation`, and `maturity_descriptions`.
- `AssessmentResults` — the aggregate (lists of both, category scores, overall score).
- `OrganizationAssessmentResults` — successful and failed account results plus aggregate average/minimum/maximum scores and summary-report metadata.

### How a discovery check runs

`execute_discovery_check()` dispatches on `check.command`:

- Custom command strings map to named methods in `discovery/executor.py`.
  Unknown custom commands fail instead of being sent to the AWS CLI.
- Otherwise `command` is a literal AWS CLI string, run through `run_aws_command()`.

`run_aws_command()` delegates to `AwsRunner` in `aws.py`. The runner injects
`--profile`/`--region`, retries on throttling, parses JSON, and always runs
tokenized arguments via `shlex.split()` without a local shell. Shell syntax
inside quoted SSM script arguments is passed to SSM for remote execution.
Pass dynamic command values through `_sanitize()`.

### Adding a new discovery check

1. Add a fixed `CheckSpec` in `discovery/check_specs.py` with a unique key
   and ID.
2. For checks needing multiple requests or processing steps, add a
   `custom_...` entry in `discovery/executor.py` and an `execute_..._check()`
   method in the appropriate discovery module.
3. Add the appropriate CSV-export handling in `export_check_result_to_csv()`. Checks 1–11, 15 (CloudWatch cross-account observability), and 29 (Transaction Search) have dedicated branches, as do checks 51–52 (CloudWatch Omni), which export active/total counts. The remaining checks 12–50 fall through to a generic binary yes/no handler. Add a dedicated branch when adding checks beyond 52.
4. Wire its result into the relevant `assess_*_maturity()` method — note these methods currently locate discovery checks **by their exact `name` string**, so name changes there are breaking.

### Scoring model

Each `assess_*_maturity()` method contains per-question `if question_id == N:` blocks with hardcoded level thresholds (e.g. Q1: "coverage >= 0.75 AND has_structured_json AND has_centralization" → level 3, plus "has_eks_addon OR has_anomaly_detection" → level 4). Maturity is rule-based and deterministic — there is no ML in the scoring (see the AI/ML security and compliance section of `ASSESSMENT_METHODOLOGY.md`). If you change what a check returns, the downstream threshold logic in these blocks likely needs updating too.

## Deployment (CloudFormation)

- `1-observability-assessment-role.yaml` — creates `ObservabilityAssessmentRole`, which is almost entirely read-only except for the scoped `ssm:SendCommand` permission used by the EC2 CloudWatch agent check. Deploy it in each target account for cross-account/multi-account mode.
- `2-observability-assessment-codebuild.yaml` creates the report buckets,
  CodeBuild project and role, and a Lambda custom resource that starts the
  first build. The buildspec updates AWS CLI v2, clones the repository given by
  `AssessmentRepoUrl` (default
  `https://github.com/aws-samples/sample-aws-observability-assessment.git`) at
  `AssessmentGitRef`, runs the assessment, and uploads HTML, CSV, and a
  timestamped ZIP report bundle. `ExpectedAssessmentCommitSha` can pin the
  checked-out commit.
- For single-account mode, set `CreateAssessmentRole=yes` (the default) and leave `AssessmentAccounts` and `AssessmentOUs` empty. CodeBuild invokes the tool with `--role-arn` for the role created in the same account.
- For multi-account mode, deploy template 1 to the target accounts, set `CreateAssessmentRole=no` in the central account, and provide either `AssessmentAccounts` or `AssessmentOUs`. `MultiAccountAssessment` assumes the target role separately in each account.

## Conventions & gotchas

- **Before every commit**, run `ruff check .`, `ruff format --check .`, and the full test suite (`python3 -m unittest discover -s tests`), and fix any failures before committing.
- **Read-only by design.** Nearly every AWS interaction is `describe`/`list`/`get`, and the IAM policy in the role template grants read actions. The **one exception** is the EC2 CloudWatch agent check, which calls `ssm:SendCommand` (via the managed `AWS-RunShellScript` document) to run a read-only diagnostic on SSM-managed instances — it does not modify instances and is skipped for non-SSM-managed ones. Do not introduce any other mutating AWS call, and do not extend `SendCommand` usage to anything that changes state.
- `assessment-result/` is gitignored. The committed examples are `sample-result/observability_assessment_single_account_sample.html` and the scrubbed multi-account bundle under `sample-result/org-scan-sample/`.
- The target-account role template trusts the exact provided CodeBuild role. Local multi-account runs require a separately authorized principal in every target role trust policy.
- Most checks are scoped to the selected region and several use bounded samples. Read `ASSESSMENT_METHODOLOGY.md` before changing scope or scoring behavior.
- License is MIT-0; keep the `Copyright Amazon.com` / `SPDX-License-Identifier: MIT-0` header on source files.
- The `# nosec` / `# nosemgrep` comments on the subprocess calls are intentional (audited) — keep them when editing those lines.
