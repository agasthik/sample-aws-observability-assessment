# Cleanup

Delete the resources in the reverse order they were created. CloudFormation
cannot delete a stack while dependent resources it does not own still exist, so
empty the retained S3 buckets and remove StackSet instances before deleting
their parent resources. Replace Region and identifiers with the values you
deployed.

## 1. Empty and delete the report buckets

The reports bucket and its access-log bucket are declared with
`DeletionPolicy: Retain` and have versioning enabled, so deleting the CodeBuild
stack leaves both buckets and their contents in place. Empty every object
version from each bucket, then delete the buckets. Find the reports bucket name
from the stack's `ReportBucketName` output; the access-log bucket is named in
the stack's resources.

```bash
REPORT_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name ObservabilityAssessmentCodeBuild \
  --query "Stacks[0].Outputs[?OutputKey=='ReportBucketName'].OutputValue" \
  --output text --region us-west-2)

# Deleting a bucket requires removing all object versions and delete markers
# first because versioning is enabled.
aws s3 rm "s3://$REPORT_BUCKET" --recursive --region us-west-2
aws s3api delete-bucket --bucket "$REPORT_BUCKET" --region us-west-2
```

Repeat the empty-and-delete steps for the access-log bucket. If a bucket still
reports objects on deletion, remaining noncurrent versions or delete markers
must be purged (for example with `aws s3api list-object-versions` and
`delete-objects`) before `delete-bucket` succeeds. Preserve any report history
you need before emptying the buckets, because this is irreversible.

## 2. Delete the CodeBuild stack

With the buckets emptied, delete the stack that created the CodeBuild project,
its IAM role, the Lambda trigger, and the bucket resources. In single-account
mode (`CreateAssessmentRole=yes`), this stack also created the assessment role
and removes it here.

```bash
aws cloudformation delete-stack \
  --stack-name ObservabilityAssessmentCodeBuild --region us-west-2
aws cloudformation wait stack-delete-complete \
  --stack-name ObservabilityAssessmentCodeBuild --region us-west-2
```

## 3. Remove the assessment role from target accounts

Skip this step in single-account mode; the role was deleted with the CodeBuild
stack in step 2. For multi-account deployments, remove the role you deployed
with `1-observability-assessment-role.yaml`.

For standalone per-account stacks, delete the stack with credentials for each
target account:

```bash
aws cloudformation delete-stack \
  --stack-name ObservabilityAssessmentRole --region us-west-2
aws cloudformation wait stack-delete-complete \
  --stack-name ObservabilityAssessmentRole --region us-west-2
```

For a service-managed StackSet, delete the stack instances first, then the
StackSet itself. Use the same `--call-as` value you deployed with
(`DELEGATED_ADMIN` from a registered delegated administrator account, or `SELF`
in the Organizations management account):

```bash
STACKSET_CALL_AS=DELEGATED_ADMIN

OPERATION_ID=$(aws cloudformation delete-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-west-2 --no-retain-stacks \
  --call-as "$STACKSET_CALL_AS" --region us-west-2 \
  --query OperationId --output text)

aws cloudformation describe-stack-set-operation \
  --stack-set-name ObservabilityAssessmentRole \
  --operation-id "$OPERATION_ID" --call-as "$STACKSET_CALL_AS" \
  --query 'StackSetOperation.[Status,StatusReason]' --output table \
  --region us-west-2

# After the instance-deletion operation reports SUCCEEDED:
aws cloudformation delete-stack-set \
  --stack-set-name ObservabilityAssessmentRole \
  --call-as "$STACKSET_CALL_AS" --region us-west-2
```

If you deployed template 1 as a standalone stack in the Organizations
management account so that account could also be assessed, delete that stack
separately as shown above.

## 4. Remove the Organizations resource policy

If you added the
[Organizations resource policy](MULTI_ACCOUNT.md#organizations-resource-policy-for-delegated-tooling-accounts)
to grant OU discovery to a delegated tooling account, remove the statement you
added once no tooling account still needs it. If that statement is the only one
in the policy, delete the resource policy from the management account:

```bash
aws organizations delete-resource-policy
```

If the policy carries other statements you rely on, edit it with
`aws organizations put-resource-policy` to remove only the
`AllowObservabilityAssessmentAccountDiscovery` statement instead of deleting the
whole policy.

## 5. Delete local output

Local runs write reports under `assessment-result/`, which is gitignored.
Remove that directory to clear local reports.
