# Assessment Methodology and Current Limitations

This document describes how the current implementation collects evidence, assigns maturity
levels, and aggregates multi-account results. It is intended to make assessment output
interpretable without overstating its coverage.

## Assessment model

The tool registers 50 discovery checks and maps their results to 17 maturity questions:

| Category | Questions |
|---|---|
| Logs | Q1–Q4 |
| Metrics | Q5–Q7 |
| Traces | Q8–Q9 |
| Dashboards & Alerting | Q10–Q12 |
| Organization | Q13–Q17 |

Each question receives an integer level from 1 through 4. The overall score is the
equal-weight arithmetic mean of all 17 question levels. Category scores are the equal-weight
mean of the questions in that category.

The rules are deterministic Python conditions in
`observability_assessment_comprehensive.py`; the assessment tool itself does not use a model
to select maturity levels.

## Regional scope

`--region` selects the primary assessment region and defaults to `us-west-2`. Most resource
discovery is performed only in that region. A multi-account run repeats that same selected
region in every target account; it is not an all-regions inventory.

Current exceptions include:

- the AWS DevOps Agent check, which checks `us-east-1` and the selected region;
- the CloudWatch Logs centralization-rule query, which requests all-region rule summaries;
- global or account-level APIs whose results are not region-specific.

The per-account report header currently shows the account and generation time. Individual
evidence entries include the region, but the organization summary does not display the
selected region. Preserve the run command or build configuration with exported reports.

## Bounded and heuristic checks

Several checks intentionally limit work to keep the assessment practical:

| Check area | Current scope |
|---|---|
| EC2 CloudWatch Agent process and logging configuration | First 5 SSM-managed running instances |
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

Review the discovery evidence before using these signals as compliance controls.

## Discovery status and empty results

A discovery check is currently marked `success` when its execution returns any value other
than `None`. This means `success` indicates that the check returned a result; it does not mean
the assessed control is configured.

Literal AWS CLI command failures generally return `None` and are marked as errors. Several
multi-step custom checks catch exceptions and return an empty or zero-valued structure
instead. In those cases, an unavailable API result can look like an evaluated result with no
resources.

When a result is unexpected:

1. Re-run the relevant check with `--single-check N --debug`.
2. Confirm that the assessment principal has every action listed in the role template.
3. Review the command and evidence in the HTML report.
4. Treat empty custom-check results as inconclusive until permissions and service
   availability are confirmed.

The CSV does not currently include a separate error/status column. For checks 12–50, most
rows use a generic binary non-empty-result indicator rather than a complete resource count.

## Automated and manual maturity evidence

Most maturity levels are selected from AWS configuration evidence. However, some questions
represent organizational practices that cannot be established from service configuration
alone.

Q16 and Q17 can assign all four levels from combinations of configuration evidence:

- Q16 uses resource tagging, cross-account observability, dashboards, sampled structured-log
  coverage, Application Signals, and SLOs. Levels 3 and 4 require increasingly broad evidence
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
5. Averages the scores of successful account assessments.

Accounts that fail before producing an assessment are listed separately and are excluded
from average, minimum, and maximum scores. The summary does not currently calculate an
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

The CodeBuild buildspec downloads the assessment script from the repository's current
`main` branch and updates the AWS CLI to the latest available v2 release on every build.
Consequently, two runs from the same deployed CloudFormation stack can use different code or
CLI versions.

Reports include generation timestamps but do not currently record the Git commit, assessment
schema version, boto3 version, or AWS CLI version. Retain build logs when exact run
provenance is required.

## Output and sensitive data

Assessment output can contain account IDs, ARNs, resource names, account names, tags, and
configuration details. Local output is written under `assessment-result/`, which is
gitignored. CodeBuild uploads HTML, CSV, and a ZIP bundle to the retained, encrypted report
bucket.

Before committing or sharing a report publicly, follow [SCRUBBING.md](SCRUBBING.md) and
manually review the transformed output.
