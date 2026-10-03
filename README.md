# AWS Observability Assessment Tool

Evaluate observability maturity across AWS environments with 52 discovery
checks covering logs, metrics, traces, dashboards and alerting, and
organizational practices. The tool generates HTML reports with maturity
scores, supporting evidence, and recommendations.

**[View the sample assessment report][sample-report]** (generated with the
previous report layout; new reports use the Cloudscape UI described below).

## Table of Contents

- [Quick Start](#quick-start)
  - [Run locally](#run-locally)
  - [Deploy with CodeBuild](#deploy-with-codebuild)
- [Multi-Account Assessment](#multi-account-assessment)
- [CLI Options](#cli-options)
- [Assessment Coverage and Methodology](#assessment-coverage-and-methodology)
- [Output](#output)
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

For assessments spanning multiple accounts, continue to
[Multi-Account Assessment](#multi-account-assessment).

## Multi-Account Assessment

Multi-account mode runs CodeBuild in a central assessment account, assumes
`ObservabilityAssessmentRole` in each target account, and produces an
organization summary plus reports for accounts that completed successfully.
Check the summary's succeeded and failed account counts and confirm the
expected per-account files. A build can succeed even if all target accounts
failed assessment, because the summary report is still generated.

### Recommended central account

For organization-wide scans, run CodeBuild from a delegated administrator
member account, such as a dedicated security, tooling, or observability
account, rather than the Organizations management account. This follows the
AWS [best practices for the management account][orgs-mgmt-best-practices],
which recommend keeping workloads and day-to-day tooling out of the management
account and limiting access to it.

With a delegated administrator central account:

- Deploy the target role StackSet with `--call-as DELEGATED_ADMIN` after
  [registering the account as a StackSets delegated administrator][stacksets-delegated-admin].
- Grant OU discovery with the
  [Organizations resource policy](#organizations-resource-policy-for-delegated-tooling-accounts),
  which is applied once from the management account. Registering a delegated
  administrator for another service does not grant these operations.
- Deploy template 1 as a standalone stack in the management account only if
  that account must also be assessed.

### 1. Deploy the assessment role to target accounts

#### Standalone target-account deployment

For a small number of accounts, deploy
`1-observability-assessment-role.yaml` separately in each target account.

Run this command with credentials for each target account:

```bash
CENTRAL_ID=123456789012

aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue="$CENTRAL_ID" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

#### Organization-scale StackSet deployment

For organization-scale deployment, use a service-managed CloudFormation
StackSet. Use `DELEGATED_ADMIN` from a registered StackSets delegated
administrator account (recommended) or `SELF` in the Organizations management
account; both StackSets commands need the same `--call-as` value:

```bash
CENTRAL_ID=123456789012
STACKSET_CALL_AS=DELEGATED_ADMIN

aws cloudformation create-stack-set \
  --stack-set-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue="$CENTRAL_ID" \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --call-as "$STACKSET_CALL_AS" \
  --region us-west-2

OPERATION_ID=$(aws cloudformation create-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-west-2 \
  --operation-preferences FailureToleranceCount=5,MaxConcurrentCount=6 \
  --call-as "$STACKSET_CALL_AS" --region us-west-2 \
  --query OperationId --output text)

aws cloudformation describe-stack-set-operation \
  --stack-set-name ObservabilityAssessmentRole \
  --operation-id "$OPERATION_ID" --call-as "$STACKSET_CALL_AS" \
  --query 'StackSetOperation.[Status,StatusReason]' --output table \
  --region us-west-2
aws cloudformation list-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --call-as "$STACKSET_CALL_AS" --region us-west-2 --output table
```

Wait until the operation completes and inspect every target stack instance
before deploying the central CodeBuild project. `FailureToleranceCount=5` can
permit a successful operation even when some instances failed, so verify the target
roles exist in every account you intend to assess. For standalone role stacks,
wait for stack creation to complete in each account. Run these commands after
enabling
[trusted access for StackSets][stacksets-trusted-access].

IAM roles are global, so deploy this StackSet in only one Region. StackSets do
not deploy stack instances to the management account; deploy template 1 there
as a standalone stack if that account must also be assessed.

The supplied trust policy permits only the provided CodeBuild role in
`CENTRAL_ASSESSMENT_ACCOUNT_ID` to assume the target role. Extend the trust
policy deliberately if a different automation role or local principal must
assume it.

### 2. Choose how accounts are discovered

Use either:

- `AssessmentAccounts` for an explicit comma-separated list of account IDs.
  This does not require Organizations discovery permissions.
- `AssessmentOUs` to discover accounts under one or more comma-separated root
  or OU IDs. The central account must have the Organizations read operations
  used by the tool.

#### Organizations resource policy for delegated tooling accounts

If CodeBuild runs in a delegated tooling account, an Organizations resource
policy can grant those discovery operations from the management account:

```bash
aws organizations put-resource-policy --content \
  '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowObservabilityAssessmentAccountDiscovery",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::CENTRAL_ASSESSMENT_ACCOUNT_ID:root"
        },
        "Action": [
          "organizations:ListAccounts",
          "organizations:ListAccountsForParent",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:DescribeAccount",
          "organizations:DescribeOrganization"
        ],
        "Resource": "*"
      }
    ]
  }'
```

Registering a delegated administrator for another AWS service does not grant
the Organizations API operations used by this tool.

### 3. Deploy CodeBuild in the central account

Set `CreateAssessmentRole=no` because the role was deployed separately to the
target accounts. The following example assesses an explicit account list:

```bash
TARGET_ID=111111111111

aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=no \
               ParameterKey=AssessmentAccounts,ParameterValue="$TARGET_ID" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

To discover accounts by organization scope, replace `AssessmentAccounts` with
an `AssessmentOUs` parameter:

```text
ParameterKey=AssessmentOUs,ParameterValue=ou-xxxx-aaaaaaaa
```

### Optional: run multi-account mode locally

These commands work only when the target role trust policies allow your local
principal to assume `/service-role/ObservabilityAssessmentRole`:

```bash
# Explicit accounts
python3 observability_assessment_comprehensive.py \
  --profile YOUR_PROFILE \
  --region us-west-2 \
  --accounts 111111111111,222222222222

# Root or OU scope
python3 observability_assessment_comprehensive.py \
  --profile YOUR_PROFILE \
  --region us-west-2 \
  --ou ou-xxxx-aaaaaaaa,ou-xxxx-bbbbbbbb
```

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
assessed questions. Questions without evaluable evidence are shown as
**Not assessed** and excluded from the average. If none are assessed, the
overall score is **N/A** and its maturity level is **Not assessed**. Otherwise,
the report names the overall score's maturity level as follows:

| Score | Maturity level |
| --- | --- |
| Below 2.0 | Reactive |
| 2.0 to below 3.5 | Proactive |
| 3.5 to 4.0 | Autonomous |

The assessment is deterministic and rule-based, but some checks use heuristics
or limited samples. Review
[Assessment Methodology and Limitations](ASSESSMENT_METHODOLOGY.md) before using
scores for governance decisions. It explains regional scope, evidence
semantics, manual validation requirements, organization aggregation, and known
portability constraints.

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
in CodeBuild does not require Node.js. The
[hosted sample report][sample-report] still shows the previous layout until
the public sample is regenerated.

The CSV is a discovery-oriented export, not a stable versioned interchange
schema. For checks 12–50, `Found Count` is binary (1 or 0) rather than a
complete resource count: check 15 records whether cross-account observability
links or sinks exist, and the other checks record whether a non-empty result
was returned. Checks 51–52 (CloudWatch Omni) report active out of total spaces
and integrations. The `Status` column marks each row `Evaluated`, `Partial`, or
`Unavailable`. Use the
HTML evidence and methodology documentation when interpreting it.

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
[stacksets-trusted-access]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-enable-trusted-access.html
[orgs-mgmt-best-practices]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html
[stacksets-delegated-admin]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html
