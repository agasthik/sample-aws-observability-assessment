# AWS Observability Assessment Tool

[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![AWS CLI v2.37+](https://img.shields.io/badge/AWS%20CLI-v2.37%2B-orange.svg)
[![Python lint](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/python-lint.yml/badge.svg)](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/python-lint.yml)
[![cfn-lint](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/cfn-lint.yml/badge.svg)](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/cfn-lint.yml)

Evaluate observability maturity across AWS environments with 52 discovery
checks covering logs, metrics, traces, dashboards and alerting, and
organizational practices. The tool generates HTML reports with maturity
scores, supporting evidence, and recommendations.

**[View the sample assessment report][sample-report]** or the
**[sample organization summary report][sample-org-report]**, both generated
with the Cloudscape report UI described below.

## Table of Contents

- [Quick Start](#quick-start)
  - [Run locally](#run-locally)
  - [Deploy with CodeBuild](#deploy-with-codebuild)
- [Multi-Account Assessment](#multi-account-assessment)
- [CLI Options](#cli-options)
- [Assessment Coverage and Methodology](#assessment-coverage-and-methodology)
- [Output](#output)
- [Cleanup](#cleanup)
- [IAM Permissions](#iam-permissions)

## Quick Start

### Run locally

Use this option for an on-demand assessment from your workstation.

**Prerequisites:** Python 3.12+, configured AWS credentials, and
[AWS CLI v2][aws-cli-install] version 2.37.0 or later. The tool runs AWS CLI
commands, including the `devops-agent` commands introduced in version 2.34.21
and the CloudWatch Omni `cloudwatchomni` commands introduced in version 2.37.0.
On older CLI versions, the CloudWatch Omni checks (51 and 52) are reported as
not evaluated.

```bash
aws --version
pip install -r requirements.txt

python3 observability_assessment_comprehensive.py \
  --profile YOUR_PROFILE \
  --region us-west-2
```

### Deploy with CodeBuild

Use CodeBuild for a repeatable, AWS-hosted assessment. The repository includes
two CloudFormation templates:

- `1-observability-assessment-role.yaml`: Creates the assessment role in an
  account being scanned.
- `2-observability-assessment-codebuild.yaml`: Creates the CodeBuild project,
  report buckets, and CodeBuild role.

For a single-account assessment, deploy only template 2. Its default
configuration creates the assessment role in the same account.

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=yes \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

The stack starts the first build after it creates the assessment role. Stack
creation confirms that CodeBuild accepted the build request, not that the
assessment finished successfully. Wait for stack creation, then inspect the
build until its status is `SUCCEEDED` and confirm the expected HTML and CSV
files in the report bucket (`ReportBucketName` stack output):

```bash
aws cloudformation wait stack-create-complete \
  --stack-name ObservabilityAssessmentCodeBuild --region us-west-2
BUILD_ID=$(aws codebuild list-builds-for-project \
  --project-name ObservabilityAssessmentCodeBuild \
  --query 'ids[0]' --output text --region us-west-2)
aws codebuild batch-get-builds --ids "$BUILD_ID" \
  --query 'builds[0].[buildStatus,logs.deepLink]' --output text \
  --region us-west-2
```

The status may initially be `IN_PROGRESS`; repeat the last command until the
build completes. To run the assessment again:

```bash
aws codebuild start-build \
  --project-name ObservabilityAssessmentCodeBuild \
  --region us-west-2
```

The project uses a `NO_SOURCE` inline buildspec to make a shallow Git clone of
a public Git repository into `assessment-src` on each build. The repository is
selected by the `AssessmentRepoUrl` parameter, which defaults to
`https://github.com/aws-samples/sample-aws-observability-assessment.git`. Set
it to a fork or mirror URL to run the assessment from a different public
repository. The CodeBuild project runs the assessment from that checkout in
both single-account and multi-account mode. The build stays in its original
working directory, so reports are still generated under `assessment-result/`
and uploaded to Amazon S3 as HTML, CSV, and a ZIP bundle. The commit SHA is
printed in the CodeBuild log. Python dependencies are installed from the
checked-out `requirements.txt`.

`AssessmentGitRef` selects a branch or tag within `AssessmentRepoUrl` and
defaults to `main`. To hold the
source code at a known commit, set it to a published release tag and set
`ExpectedAssessmentCommitSha` to that tag's full 40-character commit SHA.
The build fails if the cloned commit does not match. A branch such as `main`
can move between builds; an expected SHA on a moving branch will cause later
builds to fail after the branch advances. Change these CloudFormation
parameters by updating the stack, then start a new build to use the new
selection. When a CloudFormation template or IAM policy changes, update the
deployed stack or StackSet before rerunning the assessment so its
infrastructure and permissions remain aligned with the current repository.

CodeBuild needs outbound HTTPS access to the host of `AssessmentRepoUrl`
(`github.com` by default) to clone the repository, the configured Python
package index to install dependencies, and
`awscli.amazonaws.com` to update the AWS CLI. This template has no VPC
configuration. If you add VPC connectivity, also configure the CodeBuild VPC
settings, required EC2 permissions for its service role, and a route to these
public endpoints (typically through NAT). See the
[CodeBuild VPC documentation](https://docs.aws.amazon.com/codebuild/latest/userguide/vpc-support.html).
If the clone or dependency installation fails, or the requested ref is
unavailable, the build fails before the assessment runs. There is no S3 source fallback.

For assessments spanning multiple accounts, see
[Multi-Account Assessment](#multi-account-assessment).

## Multi-Account Assessment

Multi-account mode runs CodeBuild in a central assessment account, assumes
`ObservabilityAssessmentRole` in each target account, and produces an
organization summary plus per-account reports. Setup has three steps:

1. Deploy `1-observability-assessment-role.yaml` to each target account, as
   standalone stacks or a service-managed StackSet.
2. Choose explicit accounts (`AssessmentAccounts`) or OU discovery
   (`AssessmentOUs`).
3. Deploy `2-observability-assessment-codebuild.yaml` in the central account
   with `CreateAssessmentRole=no`.

See the [Multi-Account Assessment guide](MULTI_ACCOUNT.md) for commands, the
recommended delegated administrator setup, and the Organizations resource
policy needed for OU discovery.

## CLI Options

| Option | Description |
| --- | --- |
| `--profile` | AWS profile to use for authentication |
| `--region` | AWS Region to assess (default: `us-west-2`) |
| `--role-arn` | IAM role ARN to assume before running checks |
| `--single-check N` | Run one discovery check by ID |
| `--single-question N` | Run and score the checks for one question (1–17) |
| `--accounts` | Comma-separated account IDs for multi-account assessment |
| `--ou` | Comma-separated root or OU IDs for account discovery |
| `--cross-account-role` | Target role name under `/service-role/` |
| `--max-workers` | Maximum parallel account assessments (default: `5`) |
| `--debug` | Enable verbose diagnostic and failed-command logging |

The default cross-account role name is `ObservabilityAssessmentRole`.

## Assessment Coverage and Methodology

The assessment runs 52 discovery checks mapped to 17 equally weighted maturity
questions:

| Category | Questions | What's assessed |
| --- | --- | --- |
| Logs | Q1–Q4 | Collection, usage, access, and retention |
| Metrics | Q5–Q7 | Collection, usage, and centralized access |
| Traces | Q8–Q9 | Instrumentation, usage, and correlation |
| Dashboards & Alerting | Q10–Q12 | Alarms, dashboards, and thresholds |
| Organization | Q13–Q17 | Strategy, SLOs, ROI, AI/ML, and RUM |


Each assessed question scores 1–4, and the overall score is the average of
assessed questions, labeled Reactive, Proactive, or Autonomous. Questions
without evaluable evidence are shown as **Not assessed** and excluded from the
average. The assessment is deterministic and rule-based, but some checks use
heuristics or limited samples. Review
[Assessment Methodology and Limitations](ASSESSMENT_METHODOLOGY.md) for score
bands, evidence semantics, and known constraints before using scores for
governance decisions.

## Output

- **Single-account HTML:**
  `observability_assessment_<timestamp>_<account_id>.html`
- **Single-account CSV:** `discovery_checks_<timestamp>_<account_id>.csv`
- **Multi-account summary:** `organization_summary_<timestamp>.html`
- **CodeBuild bundle:** `assessment-report_<UTC timestamp>.zip`
- **Local output directory:** `assessment-result/`

CodeBuild uploads the reports and ZIP bundle to the S3 report bucket. The HTML
report is the primary assessment artifact. New single-account reports use
Cloudscape components for an executive summary, report header with a light/dark
mode control, score and coverage metrics,
category charts, recommendations, and a discovery table with search, sorting,
pagination, and a right-side evidence panel opened by selecting a check.
Organization summaries show account
coverage, score ranges, category averages, and a searchable account table.
Both HTML reports end with an assessment methodology section explaining the
question levels, score calculation, and overall maturity bands.
Coverage indicators distinguish unavailable checks, unassessed questions, and
questions with partial evidence from fully assessed results.


Each HTML report embeds its report data and compiled UI assets, so it can be
opened as a single file with JavaScript enabled. Report generation uses the
compiled assets shipped with the repository; running an assessment locally or
in CodeBuild does not require Node.js.

The CSV is a discovery-oriented export, not a stable versioned interchange
schema. For checks 12–50, `Found Count` is binary (1 or 0) rather than a
complete resource count: check 15 records whether cross-account observability
links or sinks exist, and the other checks record whether a non-empty result
was returned. Checks 51–52 (CloudWatch Omni) report active out of total spaces
and integrations. The `Status` column marks each row `Evaluated`, `Partial`, or
`Unavailable`. Use the
HTML evidence and methodology documentation when interpreting it.

## Cleanup

The report buckets are retained when the CodeBuild stack is deleted, and
multi-account deployments leave target-account roles and StackSets in place.
Follow the [Cleanup guide](CLEANUP.md) to empty the buckets and remove the
stacks, StackSets, and Organizations resource policy in the correct order.

## IAM Permissions

The assessment uses APIs across these service groups:

- **Observability:** Amazon CloudWatch, CloudWatch Logs, AWS X-Ray, CloudWatch
  Application Signals, CloudWatch Synthetics, CloudWatch RUM, CloudWatch
  Observability Access Manager, and CloudWatch Observability Admin
- **Workloads and resources:** Amazon EC2, AWS Lambda, Amazon ECS, Amazon EKS,
  AWS Systems Manager, Amazon Kinesis Data Streams, Amazon Data Firehose, the
  Resource Groups Tagging API, and AWS DevOps Agent
- **Organization discovery:** AWS Organizations

Almost all actions are read-only (`Describe*`, `List*`, and `Get*`). See
`1-observability-assessment-role.yaml` for the complete policy.

The exception is the EC2 CloudWatch agent check, which uses `ssm:SendCommand`
with the AWS-managed `AWS-RunShellScript` document to determine whether the
agent is running and log collection is configured. It does not intentionally
modify instances and is skipped for instances not managed by Systems Manager.

There is no CLI option to disable only this check during a full assessment. If
your environment prohibits `ssm:SendCommand`, run selected checks or questions,
or omit that permission and treat the EC2 agent evidence as unavailable.

[aws-cli-install]: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
[sample-report]: https://aws-samples.github.io/sample-aws-observability-assessment/sample-result/observability_assessment_sample.html
[sample-org-report]: https://aws-samples.github.io/sample-aws-observability-assessment/sample-result/org-scan-sample/organization_summary_20261003_050758.html
