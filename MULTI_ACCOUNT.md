# Multi-Account Assessment

This guide deploys the assessment across multiple AWS accounts. For a
single-account assessment, see the [Quick Start](README.md#quick-start). To
remove the resources afterward, see [Cleanup](CLEANUP.md).

## Contents

- [Recommended central account](#recommended-central-account)
- [1. Deploy the assessment role to target accounts](#1-deploy-the-assessment-role-to-target-accounts)
- [2. Choose how accounts are discovered](#2-choose-how-accounts-are-discovered)
- [3. Deploy CodeBuild in the central account](#3-deploy-codebuild-in-the-central-account)
- [Optional: run multi-account mode locally](#optional-run-multi-account-mode-locally)

Multi-account mode runs CodeBuild in a central assessment account, assumes
`ObservabilityAssessmentRole` in each target account, and produces an
organization summary plus reports for accounts that completed successfully.
Check the summary's succeeded and failed account counts and confirm the
expected per-account files. A build can succeed even if all target accounts
failed assessment, because the summary report is still generated.

## Recommended central account

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

## 1. Deploy the assessment role to target accounts

### Standalone target-account deployment

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

### Organization-scale StackSet deployment

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

## 2. Choose how accounts are discovered

Use either:

- `AssessmentAccounts` for an explicit comma-separated list of account IDs.
  This does not require Organizations discovery permissions.
- `AssessmentOUs` to discover accounts under one or more comma-separated root
  or OU IDs. The central account must have the Organizations read operations
  used by the tool.

### Organizations resource policy for delegated tooling accounts

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

## 3. Deploy CodeBuild in the central account

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

## Optional: run multi-account mode locally

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

[stacksets-trusted-access]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-enable-trusted-access.html
[orgs-mgmt-best-practices]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html
[stacksets-delegated-admin]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html
