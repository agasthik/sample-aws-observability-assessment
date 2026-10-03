# Assessment Methodology and Current Limitations

This document describes how the current implementation collects evidence, assigns maturity
levels, and aggregates multi-account results. It is intended to make assessment output
interpretable without overstating its coverage.

## Assessment model

The tool registers 52 discovery checks and maps their results to 17 maturity questions:

| Category | Questions |
| --- | --- |
| Logs | Q1–Q4 |
| Metrics | Q5–Q7 |
| Traces | Q8–Q9 |
| Dashboards & Alerting | Q10–Q12 |
| Organization | Q13–Q17 |

Each question with evaluable evidence receives an integer level from 1 through 4. A
question whose evidence checks all fail is marked **Not assessed**. The overall
score is the equal-weight arithmetic mean of assessed question levels; category
scores average assessed questions in that category. If no questions are assessed,
the report displays N/A instead of a maturity score.

The overall score is labeled with a maturity level. Organization summaries apply the same
bands to the average and best account scores, and per-question recommendations name the
level they lead to (Level 1 is Reactive, Levels 2 and 3 are Proactive, Level 4 is
Autonomous):

| Score | Maturity level |
| --- | --- |
| Below 2.0 | Reactive |
| 2.0 to below 3.5 | Proactive |
| 3.5 to 4.0 | Autonomous |

The rules are deterministic Python conditions in
`observability_assessment/scoring/`; the assessment tool itself does not use a
model to select maturity levels.

### Discovery catalog changes from the previous script

Checks 1–50 retain their IDs and categories. Checks 51–52 add CloudWatch Omni
discovery. Five literal commands changed so that results reflect active
configuration rather than mere presence:

| ID | Command change |
| --- | --- |
| 12 | Excludes `PAUSED`, `DELETED`, and `FAILED` log anomaly detectors. |
| 24 | Adds `--recently-active PT3H` so only CloudWatch agent metrics published in the last three hours count. |
| 25 | Counts only metric streams in the `running` state. |
| 29 | Uses `aws xray get-trace-segment-destination` (destination `CloudWatchLogs`, status `ACTIVE`) instead of the presence of the `aws/spans` log group. |
| 38 | Excludes resources whose tag list is empty. |

Thirteen existing display names changed; consumers
that join report or CSV rows by name should use the stable check ID where
available or update their name mapping. `tests/discovery_catalog.json` captures
the current catalog, rather than the previous script's names.

| ID | Previous display name | Current display name |
| --- | --- | --- |
| 1 | What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs) | What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)? |
| 2 | What percentage of log groups have retention policies configured (example thresholds: …)? | What percentage of the largest log groups have retention policies configured (example thresholds: …)? |
| 3 | Do you have standardized Log Insights queries for common troubleshooting scenarios (errors, latency, security events)? | Do you have standardized Logs Insights queries for common troubleshooting scenarios (errors, latency, security events)? |
| 4 | Do you have a history of Log Insights queries being executed? | Do you have a history of Logs Insights queries being executed? |
| 6 | What percentage of log groups have subscription filters for real-time processing? | What percentage of the largest log groups have subscription filters for real-time processing? |
| 7 | What percentage of EC2 instances have CloudWatch Agent installed with both system metrics AND application logs configured? | What percentage of EC2 instances have the CloudWatch agent installed with both system metrics AND application logs configured? |
| 14 | Have you implemented Cross-Account and Cross-Region Log Centralization? | Have you implemented cross-account and cross-Region log centralization? |
| 19 | What percentage of ECS Clusters have monitoring enabled? | How many ECS clusters are available to monitor? |
| 21 | Do you have EKS clusters with CloudWatch Observability add-on enabled? | Do you have EKS clusters with the CloudWatch Observability add-on enabled? |
| 24 | Are CloudWatch Agents configured to collect system-level metrics? | Is the CloudWatch agent configured to collect system-level metrics? |
| 29 | Do you have transaction search enabled? | Do you have Transaction Search enabled? |
| 44 | Have you configured CloudWatch Investigations action for any alarms? | Have you configured CloudWatch Investigations actions for any alarms? |
| 47 | Do you use AWS Application Signals to monitor application services? | Do you use CloudWatch Application Signals to monitor application services? |

## Regional scope

`--region` selects the primary assessment Region and defaults to `us-west-2`. Most resource
discovery is performed only in that Region. A multi-account run repeats that same selected
Region in every target account; it is not an all-Regions inventory.

Current exceptions include:

- the AWS DevOps Agent check, which checks `us-east-1` and the selected Region;
- the CloudWatch Omni checks, which list domains, spaces, and integrations in the selected
  Region only, so spaces in other Regions are not counted;
- the CloudWatch Logs centralization-rule query, which requests all-Region rule summaries;
- global or account-level APIs whose results are not Region-specific.

The per-account report header shows the account, selected Region, and generation time.
The organization summary does not display the selected Region. Preserve the run
command or build configuration with exported reports.

## Bounded and heuristic checks

Several checks intentionally limit work to keep the assessment practical:

| Check area | Current scope |
| --- | --- |
| EC2 CloudWatch agent process and logging configuration | First 5 SSM-managed running instances |
| Lambda JSON logging configuration | First 20 listed functions; reported total is the full listed population |
| ECS task logging | First 3 listed clusters |
| EKS control-plane logging | First 5 listed clusters |
| Log retention | 10 largest log groups |
| Log field indexes | 20 largest non-system log groups |
| Subscription filters, structured-log proxy, and stale-log analysis | Up to 10 largest identified log groups for each of EC2, ECS, Lambda, and EKS |
| Alarm action checks | First 50 metric and composite alarms combined |
| Application Signals services | Services observed in the preceding one-hour window |

These results are indicators, not exhaustive inventory, when the population exceeds the
listed bound.

Some checks are heuristic:

- application structured logging is inferred from configured custom field indexes on selected
  log groups;
- Lambda structured logging is inferred from known environment-variable conventions;
- ECS structured logging currently treats supported task logging drivers as evidence of
  logging configuration and does not parse emitted events;
- compute types in use are inferred partly from log-group naming patterns;
- stale log groups are selected from the largest inferred compute log groups and use a
  90-day ingestion threshold.

Q1 counts a compute type as having logging only when its discovery check
succeeded and found at least one configured resource: EC2 instances with
CloudWatch agent logging, Lambda functions with JSON logging, ECS tasks with
logging, or EKS control-plane log types enabled. A successful check reporting
zero configured resources gives no coverage credit. This can lower Q1 compared
with the previous script, which credited a successful check even at 0%.

Review the discovery evidence before using these signals as compliance controls.

## Discovery status and empty results

A discovery check is currently marked `success` when its execution returns any value other
than `None`. This means `success` indicates that the check returned a result; it does not mean
the assessed control is configured.

Literal AWS CLI command failures generally return `None` and are marked as errors. Several
multi-step custom checks catch exceptions and return an empty or zero-valued structure
instead. In those cases, an unavailable API result can look like an evaluated result with no
resources.

The report marks a question **Not assessed** when none of its evidence checks
could be evaluated. If some evidence is available but other checks failed or
returned incomplete data, the question keeps a score and is flagged as
**Partial evidence**. Review its check details before relying on that score.

When a result is unexpected:

1. Re-run the relevant check with `--single-check N --debug`.
2. Confirm that the assessment principal has every action listed in the role template.
3. Review the command and evidence in the HTML report.
4. Treat empty custom-check results as inconclusive until permissions and service
   availability are confirmed.

The CSV has a `Status` column (`Evaluated`, `Partial`, or `Unavailable`).
For checks 12–50, most rows use a generic binary non-empty-result indicator
rather than a complete resource count. Text cells that could be interpreted as
spreadsheet formulas are prefixed with a tab and quoted in the CSV. Leading
tabs and newlines in those cells are written as visible escapes. Programmatic
CSV readers retain these prefixes and escapes.

## CloudWatch Omni checks

Checks 51 and 52 use only account-level CloudWatch Omni list operations
(`ListSpaces`, `ListDomains`, and `ListIntegrations`), which the assessment role is granted
through IAM. Omni also authorizes requests inside a space through space access grants, and the
assessment role is not given one, so the tool does not inspect Omni alerts, Omni dashboards,
access grants, or queried telemetry.

- An active space counts as unified access to logs (Q3) and metrics (Q7), in the same way as
  CloudWatch cross-account observability or log centralization.
- A space whose domain is an organization domain counts toward the enterprise-scope signal in
  Q16.
- If spaces cannot be listed (for example, missing permissions, an older AWS CLI, or Omni not
  being available in the selected Region), check 51 is marked as an error rather than as "no
  Omni". Check 52 behaves the same way for integrations.
- Spaces that are suspended or moving are listed in the evidence but do not affect scoring.

## Automated and manual maturity evidence

Most maturity levels are selected from AWS configuration evidence. However, some questions
represent organizational practices that cannot be established from service configuration
alone.

Q16 and Q17 can assign all four levels from combinations of configuration evidence:

- Q16 uses resource tagging, cross-account observability (OAM or an active CloudWatch Omni
  space in an organization domain), dashboards, sampled structured-log coverage, Application
  Signals, and SLOs. Active Omni integrations are reported as context and do not change the
  level. Levels 3 and 4 require increasingly broad evidence
  of standardization and enterprise integration.
- Q17 uses consolidated dashboards and alarms together with sampled retention coverage,
  archival, tagging, composite alarms, active log use, and SLOs. Level 4 requires both strong
  cost-governance evidence and a business-alignment proxy through formal SLOs.

These are technical proxies. AWS configuration cannot prove that teams receive training, that
leadership drives a continuous-improvement culture, or that observability has produced measured
financial returns. The report therefore retains manual validation questions in its explanation
for the higher levels. The tool has no manual answer override.

## Multi-account aggregation

Multi-account mode:

1. Discovers accounts from explicit IDs or AWS Organizations.
2. Assumes `/service-role/ObservabilityAssessmentRole` in each target account.
3. Runs accounts concurrently, using `--max-workers` with a default of 5.
4. Produces one timestamped report and CSV per successful account.
5. Averages the scores of successful accounts with at least one assessed question.

Accounts that fail before producing an assessment are listed separately and are excluded
from average, minimum, and maximum scores. A successful account with no assessed
questions appears as **Not assessed** and is also excluded from score
aggregation. The organization report shows both the count of successful accounts
and the count that contributed to scores. It also flags accounts with unavailable
checks or partial evidence. The summary does not currently calculate an
evidence-completeness or confidence score for successful accounts.

## Cross-account trust and partition support

The supplied target-account role trusts the exact
`ObservabilityAssessmentCodeBuildRole` principal in the configured assessment account. Local
profiles and differently named automation roles need an explicit trust-policy change before
they can assume it.

Multi-account role ARNs are currently constructed with the commercial `arn:aws` partition.
The single-account CloudFormation resources use `AWS::Partition`, but the Python
multi-account path has not been generalized for AWS GovCloud (US) or AWS Regions in China.

## Reproducibility

The CodeBuild buildspec clones the repository given by `AssessmentRepoUrl`
(default `https://github.com/aws-samples/sample-aws-observability-assessment.git`)
at the configured
`AssessmentGitRef` (default `main`), installs its `requirements.txt`, and
updates the AWS CLI to the latest available v2 release on every build. The
optional `ExpectedAssessmentCommitSha` parameter causes a build to fail when
the checked-out commit differs. A fixed source commit does not pin the runtime:
`requirements.txt` allows newer boto3 releases, and the CLI update is
unversioned. Two runs from the same deployed stack can therefore use different
source commits or dependency versions.

Reports include generation timestamps but do not currently record the Git
commit, assessment schema version, boto3 version, or AWS CLI version. The
resolved Git commit is printed in CodeBuild logs. Retain build logs when exact
run provenance is required.

## Output and sensitive data

Assessment output can contain account IDs, ARNs, resource names, account names, tags, and
configuration details. Local output is written under `assessment-result/`, which is
gitignored. CodeBuild uploads HTML, CSV, and a ZIP bundle to the retained, encrypted report
bucket.

Before committing or sharing a report publicly, follow [SCRUBBING.md](SCRUBBING.md) and
manually review the transformed output.

## AI/ML security and compliance

The assessment tool references and recommends the following AWS AI/ML services as part of
observability maturity assessment:

1. **Amazon CloudWatch anomaly detection** — ML-based metric anomaly detection
2. **Amazon CloudWatch Investigations** — AI-assisted incident investigation
3. **AWS DevOps Agent** — AI-assisted troubleshooting via natural language

The tool does not train, fine-tune, or deploy any AI/ML models. It only checks whether these
AWS-managed services are configured in the assessed account.

### The assessment tool performs no AI/ML inference

As described under [Assessment model](#assessment-model) and
[Automated and manual maturity evidence](#automated-and-manual-maturity-evidence), the
maturity scoring algorithm is deterministic and rule-based, defined in
`observability_assessment/scoring/` and applied uniformly across all assessed accounts. The
tool performs no inference, prediction, or generative AI. Its interaction with the AI/ML
services above is limited to configuration-presence checks:

- Calls `cloudwatch:DescribeAnomalyDetectors` to check whether anomaly detection is configured
- Calls the AWS DevOps Agent API to check whether agent spaces exist
- Checks CloudWatch Investigations alarm actions for configuration presence

No demographic or personal data is collected or used in scoring. AI/ML service
recommendations are based solely on whether the service is configured, not on the quality or
nature of the data being analyzed.

### Security controls of the referenced services

The referenced services share these characteristics: they operate on observability data
(metrics, logs, and traces) that already exists in the customer's account; the underlying
models are fully managed by AWS and are not accessible to customers; no customer data is
shared across accounts or used to train or improve the models; access is governed by IAM
policies; and CloudWatch Investigations and the AWS DevOps Agent must be explicitly enabled
by the customer. Amazon CloudWatch anomaly detection operates on metric data that stays
within the AWS Region where it is collected.

### Compliance and legal notes

- All referenced AI/ML services are AWS-managed and covered under the
  [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/).
- The tool does not train, fine-tune, or deploy AI/ML models, so no dataset compliance review
  is required for the tool itself.
- Customers enabling AWS AI/ML services in their accounts are responsible for reviewing the
  applicable [AWS Service Terms](https://aws.amazon.com/service-terms/) and the
  [AWS AI Service Cards](https://aws.amazon.com/machine-learning/responsible-machine-learning/)
  — including bias and fairness information — for each service they enable.
- No customer data is sent to external AI/ML endpoints; all processing occurs within the
  customer's AWS account and Region. No third-party AI/ML services or models are used.
- The tool's recommendations to enable AI/ML services are informational only — customers
  should obtain appropriate internal approvals before enabling AI/ML services in production
  environments.
