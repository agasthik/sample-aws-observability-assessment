# AWS Observability Assessment Tool

Evaluate observability maturity across AWS environments with 50 discovery checks covering logs, metrics, traces, dashboards and alerting, and organizational practices. The tool generates HTML reports with maturity scores, supporting evidence, and recommendations.

**[View the sample assessment report](https://aws-samples.github.io/sample-aws-observability-assessment/sample-result/observability_assessment_sample.html)**

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

**Prerequisites:** Python 3.12+, configured AWS credentials, and [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) version 2.34.21 or later. The tool runs AWS CLI commands, including the `devops-agent` commands introduced in version 2.34.21.

```bash
aws --version
pip install -r requirements.txt

python3 observability_assessment_comprehensive.py \
  --profile YOUR_PROFILE \
  --region us-west-2
```

### Deploy with CodeBuild

Use CodeBuild for a repeatable, AWS-hosted assessment. The repository includes two CloudFormation templates:

| Template | Purpose |
|----------|---------|
| `1-observability-assessment-role.yaml` | Creates the assessment role in an account being scanned |
| `2-observability-assessment-codebuild.yaml` | Creates the CodeBuild project, report buckets, and CodeBuild role |

For a single-account assessment, deploy only template 2. Its default configuration creates the assessment role in the same account.

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=yes \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

The stack automatically starts the first build. To run the assessment again:

```bash
aws codebuild start-build \
  --project-name ObservabilityAssessmentCodeBuild \
  --region us-west-2
```

The project downloads the assessment script from the repository's `main` branch on each build and uploads the generated HTML, CSV, and ZIP files to Amazon S3. Existing deployments can therefore run newer assessment logic without a CloudFormation update. Keep the assessment role policy aligned with the current repository when checks change.

For assessments spanning multiple accounts, continue to [Multi-Account Assessment](#multi-account-assessment).

<details>
<summary><b>S3 fallback when CodeBuild cannot reach GitHub</b></summary>

Upload the assessment script to the report bucket created by template 2:

```bash
BUCKET=$(aws cloudformation describe-stacks \
  --stack-name ObservabilityAssessmentCodeBuild \
  --query 'Stacks[0].Outputs[?OutputKey==`ReportBucketName`].OutputValue' \
  --output text \
  --region us-west-2)

aws s3 cp observability_assessment_comprehensive.py "s3://$BUCKET/"
```

</details>

## Multi-Account Assessment

Multi-account mode runs CodeBuild in a central assessment account, assumes `ObservabilityAssessmentRole` in each target account, and produces an organization summary plus per-account reports.

### 1. Deploy the assessment role to target accounts

For a small number of accounts, deploy `1-observability-assessment-role.yaml` separately in each target account.

<details>
<summary><b>Standalone target-account deployment</b></summary>

Run this command with credentials for each target account:

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue=CENTRAL_ASSESSMENT_ACCOUNT_ID \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

</details>

For organization-scale deployment, use a service-managed CloudFormation StackSet:

```bash
aws cloudformation create-stack-set \
  --stack-set-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue=CENTRAL_ASSESSMENT_ACCOUNT_ID \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --region us-west-2

aws cloudformation create-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-west-2 \
  --operation-preferences FailureToleranceCount=5,MaxConcurrentCount=10
```

Run these commands from the AWS Organizations management account or a delegated StackSets administrator after enabling [trusted access for StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-enable-trusted-access.html).

IAM roles are global, so deploy this StackSet in only one Region. StackSets do not deploy stack instances to the management account; deploy template 1 there as a standalone stack if that account must also be assessed.

The supplied trust policy permits only the provided CodeBuild role in `CENTRAL_ASSESSMENT_ACCOUNT_ID` to assume the target role. Extend the trust policy deliberately if a different automation role or local principal must assume it.

### 2. Choose how accounts are discovered

Use either:

- `AssessmentAccounts` for an explicit comma-separated list of account IDs. This does not require Organizations discovery permissions.
- `AssessmentOUs` to discover accounts under one or more comma-separated root or OU IDs. The central account must have the Organizations read operations used by the tool.

If CodeBuild runs in a delegated tooling account, an Organizations resource policy can grant those discovery operations from the management account:

<details>
<summary><b>Example Organizations resource policy</b></summary>

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

</details>

Registering a delegated administrator for another AWS service does not grant the Organizations API operations used by this tool.

### 3. Deploy CodeBuild in the central account

Set `CreateAssessmentRole=no` because the role was deployed separately to the target accounts. The following example assesses an explicit account list:

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=no \
               ParameterKey=AssessmentAccounts,ParameterValue=111111111111,222222222222 \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

To discover accounts by organization scope, replace `AssessmentAccounts` with an `AssessmentOUs` parameter:

```text
ParameterKey=AssessmentOUs,ParameterValue=ou-xxxx-aaaaaaaa
```

### Optional: run multi-account mode locally

These commands work only when the target role trust policies allow your local principal to assume `/service-role/ObservabilityAssessmentRole`:

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
|--------|-------------|
| `--profile` | AWS profile to use for authentication |
| `--region` | AWS Region to assess (default: `us-west-2`) |
| `--role-arn` | IAM role ARN to assume before running checks |
| `--single-check N` | Run one discovery check by ID |
| `--single-question N` | Run and score the checks for one question (1–17) |
| `--accounts` | Comma-separated account IDs for multi-account assessment |
| `--ou` | Comma-separated root or OU IDs for account discovery |
| `--cross-account-role` | Target role name at the fixed `/service-role/` path (default: `ObservabilityAssessmentRole`) |
| `--max-workers` | Maximum parallel account assessments (default: `5`) |
| `--debug` | Enable verbose diagnostic and failed-command logging |

## Assessment Coverage and Methodology

The assessment runs 50 discovery checks mapped to 17 equally weighted maturity questions:

| Category | Questions | What's assessed |
|----------|-----------|-----------------|
| Logs | Q1–Q4 | Collection, usage, access, and retention |
| Metrics | Q5–Q7 | Collection types, usage patterns, and centralized access |
| Traces | Q8–Q9 | Instrumentation, usage, and correlation |
| Dashboards & Alerting | Q10–Q12 | Alarm strategies, dashboard maturity, and adaptive thresholds |
| Organization | Q13–Q17 | Strategy, SLOs, ROI, AI/ML, and real user monitoring |

The assessment is deterministic and rule-based, but some checks use heuristics or limited samples. Review [Assessment Methodology and Limitations](ASSESSMENT_METHODOLOGY.md) before using scores for governance decisions. It explains regional scope, evidence semantics, manual validation requirements, organization aggregation, and known portability constraints.

## Output

- **Single-account HTML:** `observability_assessment_<timestamp>_<account_id>.html`
- **Single-account CSV:** `discovery_checks_<timestamp>_<account_id>.csv`
- **Multi-account summary:** `organization_summary_<timestamp>.html`
- **CodeBuild bundle:** `assessment-report_<UTC timestamp>.zip`
- **Local output directory:** `assessment-result/`

CodeBuild uploads the reports and ZIP bundle to the S3 report bucket. The HTML report is the primary assessment artifact; see the [hosted sample report](https://aws-samples.github.io/sample-aws-observability-assessment/sample-result/observability_assessment_sample.html).

The CSV is a discovery-oriented export, not a stable versioned interchange schema. For most checks after check 11, `Found Count` indicates whether a non-empty result was returned rather than the complete resource count. Use the HTML evidence and methodology documentation when interpreting it.

## IAM Permissions

The assessment accesses Amazon CloudWatch, AWS X-Ray, AWS Lambda, Amazon ECS, Amazon EKS, Amazon SNS, AWS Systems Manager, Amazon CloudWatch Application Signals, AWS Organizations, and related services. Almost all actions are read-only (`Describe*`, `List*`, and `Get*`). See `1-observability-assessment-role.yaml` for the complete policy.

The exception is the EC2 CloudWatch agent check, which uses `ssm:SendCommand` with the AWS-managed `AWS-RunShellScript` document to determine whether the agent is running and log collection is configured. It does not intentionally modify instances and is skipped for instances not managed by Systems Manager.

There is no CLI option to disable only this check during a full assessment. If your environment prohibits `ssm:SendCommand`, run selected checks or questions, or omit that permission and treat the EC2 agent evidence as unavailable.
