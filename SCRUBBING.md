# Scrubbing Guide — Sanitizing Assessment Output for Public Release

This document defines the rules and process for sanitizing the Observability Assessment
HTML report before committing it to the public repository as a sample.

## Why Scrub?

The assessment discovers real AWS resource names, account IDs, ARNs, and infrastructure
details. While AWS account IDs are not considered secrets, resource names can reveal
internal project codenames, org structure, and deployment patterns. We scrub to:

1. Prevent leaking internal project/resource names that identify the customer or org.
2. Follow AWS documentation conventions so the sample looks professional and familiar.
3. Ensure the sample is reusable as a teaching artifact without distracting details.

## Placeholder Conventions

These follow the [AWS CLI Reference Guide example standards](https://docs.aws.amazon.com/cli/latest/userguide/welcome-examples.html)
and internal AWS documentation team conventions.

### Account & Identity

| Data Type | Placeholder Pattern | Notes |
|---|---|---|
| AWS Account ID (12-digit) | `111122223333` | For multiple accounts: `111122223333`, `444455556666`, `777788889999` |
| IAM Role ARN | `arn:aws:iam::111122223333:role/ExampleRole` | Keep the service prefix, replace the name |
| IAM User | `arn:aws:iam::111122223333:user/ExampleUser` | |
| Email addresses | Remove or replace with `user@example.com` | |

### Resource Identifiers

| Data Type | Placeholder Pattern | Notes |
|---|---|---|
| EC2 Instance ID | `i-1234567890abcdef0` | Keep `i-` prefix |
| VPC ID | `vpc-1a2b3c4d5e6f7g8h9` | Keep `vpc-` prefix |
| Subnet ID | `subnet-1a2b3c4d5e6f7g8h` | Keep `subnet-` prefix |
| Security Group ID | `sg-1a2b3c4d5e6f7g8h9` | Keep `sg-` prefix |
| EKS/ECS Cluster | `ExampleAppEKS-cluster`, `ExampleECS-cluster` | Use `Example` prefix |
| S3 Bucket | `amzn-s3-demo-bucket` or `example-bucket-name` | AWS standard demo bucket name |
| CloudFormation Stack ID | `a1b2c3d4-0001-0001-0001-abcdef012345` | Increment middle sections for multiple |
| Lambda Function | `ExampleStack-FunctionName` | Keep structural suffixes |
| Log Group | `/aws/lambda/ExampleStack-Function` | Keep AWS service prefix path |
| SNS Topic | `Default_CloudWatch_Alarms_Topic` or `ExampleTopic` | |
| CloudWatch Alarm | `ExampleApp-alarm-name` | Replace customer-specific prefixes |
| Workspace ID (AMP) | `ws-a1b2c3d4-0005-0005-0005-abcdef012345` | Keep `ws-` prefix |
| Canary ID | `cwsyn-exampleapp-canary-a1b2c3d4-...` | Keep `cwsyn-` prefix |

### UUIDs and GUIDs

| Position | Pattern |
|---|---|
| First | `a1b2c3d4-5678-90ab-cdef-EXAMPLE11111` |
| Second | `a1b2c3d4-5678-90ab-cdef-EXAMPLE22222` |
| Third | `a1b2c3d4-5678-90ab-cdef-EXAMPLE33333` |
| Short form (stack IDs) | `a1b2c3d4-0001-0001-0001-abcdef012345` (increment `0001`) |

### ARNs

Replace each component independently:
```
arn:aws:<service>:<region>:<account>:<resource-type>/<resource-name>
         ↓          ↓        ↓                         ↓
      keep      us-west-2  111122223333          ExampleResource
```

Keep the service name, resource type, and structural separators (`:`, `/`).
Only replace the account ID and resource name portions.

### Regions

Use `us-west-2` unless the resource is region-locked or multi-region context matters.

### Resource Names — The `Example*` Convention

Replace real resource names with `Example`-prefixed equivalents that preserve the
structural meaning:

| Real Pattern | Scrubbed Equivalent |
|---|---|
| `mycompany-prod-eks-cluster` | `ExampleAppEKS-cluster` |
| `petstore-microservice` | `ExampleStack-Microservices` |
| `internal-cicd-pipeline` | `ExampleStack-Pipeline` |
| `my-observability-workshop` | `ExampleWorkshop` |

Keep suffixes that convey architectural meaning (e.g., `-cluster`, `-LogGroup`,
`-pipeline`, `-Assessment`).

### Tags

CloudFormation-generated tags are generally safe to keep (they reference stack names
that are already scrubbed). Remove or replace:
- Tags containing team names, cost centers, or org-specific values
- Tags with `owner`, `contact`, or email-related keys
- Tags revealing internal project codenames

Keep:
- `environment=non-prod` / `environment=prod`
- `application=<scrubbed-name>`
- `aws:cloudformation:*` tags (after scrubbing the stack-id value)

## Process

### Manual Scrubbing Checklist

1. **Account ID**: Find/replace the 12-digit account ID → `111122223333`
2. **Resource names**: Replace project/team-specific names with `Example*` equivalents
3. **Stack IDs (UUIDs in ARNs)**: Replace with incrementing `a1b2c3d4-NNNN-...` pattern
4. **VPC/Subnet/SG IDs**: Replace with placeholder IDs keeping the prefix
5. **Instance IDs**: Replace with `i-1234567890abcdef0` pattern
6. **Dates**: Assessment generation date can stay (it's not sensitive)
7. **Metrics/counts**: Keep real numbers — they demonstrate the tool's value
8. **Log group names**: Replace custom names; keep `/aws/` service paths with scrubbed suffixes

### Automated Scrubbing

Use the provided `scripts/scrub-sample-report.py` script:

```bash
python3 scripts/scrub-sample-report.py \
    --input assessment-result/observability_assessment_20260712_164009_209466560996.html \
    --output sample-result/observability_assessment_sample.html \
    --account-id 209466560996
```

The script performs regex-based replacements in this order:

1. Account ID → `111122223333`
2. Custom resource names supplied through `--names-file`
3. Amazon Managed Service for Prometheus workspace IDs
4. Known resource ID patterns (instance, VPC, subnet, SG, ENI, and related IDs)
5. UUID/GUID patterns in stack IDs and resource identifiers
6. Email addresses

The script does not automatically discover arbitrary customer resource names or replace
every ARN resource-name component. Provide those values in `--names-file` and complete the
manual review.

**Always review the output manually** — regex can miss context-dependent names
(e.g., a log group named after an internal project that doesn't match a pattern).

Transformation mode prints post-scrub warnings but currently exits with status `0`. Do not
use that exit status alone as a release gate. After reviewing and updating any custom name
mappings, run verification-only mode; it exits nonzero when its checks find remaining
patterns:

```bash
python3 scripts/scrub-sample-report.py \
    --input sample-result/observability_assessment_sample.html \
    --output /tmp/not-used.html \
    --account-id 209466560996 \
    --verify-only
```

### Verification

After scrubbing, verify no sensitive data remains:

```bash
# Check for the real account ID
grep -c "209466560996" sample-result/observability_assessment_sample.html
# Should return 0

# Check for common resource ID patterns that weren't caught
grep -oP '\b\d{12}\b' sample-result/observability_assessment_sample.html | sort -u
# Should only show 111122223333 (or other placeholder accounts)

# Check for internal hostnames or endpoints
grep -iP '(\.corp\.|\.internal\.|amazon\.com|@)' sample-result/observability_assessment_sample.html
# Should return nothing
```

## Multi-Account / Org-Level Scrubbing

A multi-account (org) run is **not** a single file — it produces one
`organization_summary_<ts>.html` plus one `observability_assessment_<ts>_<accountid>.html`
per account, and the files **cross-link each other**. Scrubbing them needs a few extra
steps beyond the single-file flow. Learnings from scrubbing a 14-account org scan:

### 1. Every account needs its own placeholder ID

`scrub-sample-report.py --account-id` only replaces **one** ID. For an org scan, build a
`--names-file` that maps **all** real account IDs to distinct placeholders, and map real
**account names** too. Pass any one real ID to `--account-id` (redundant but required) and
let the names-file do the rest. Suggested placeholder IDs (all obviously fake, distinct):
`111122223333`, `222233334444`, `333344445555`, `444455556666`, … Assign the **management
account** to `111122223333`.

Get the account-id → name map straight from the summary drop-down:

```bash
python3 - <<'PY'
import re, glob
s = open(glob.glob('assessment-result/<run-dir>/organization_summary_*.html')[0]).read()
seen = {}
for m in re.finditer(r'([0-9]{12}) - ([^<]+)</(?:option|a)>', s):
    seen[m.group(1)] = m.group(2).strip()
for aid in sorted(seen):
    print(aid, '->', seen[aid])
PY
```

### 2. Account names — scrub aliases, keep standard governance names

Map customer/alias/codename account names to `Example*` labels. Typical offenders are
names built from a team or project codename (`<codename> Prod`, `<codename> Network`) or a
user alias plus a label (`<alias>+<label>`). **Keep** the standard AWS Control Tower account
names — `Audit`, `Log Archive`, `Sandbox 1` — they're generic and make the sample look
authentic.

### 3. Filenames embed the account ID — rename them, or links break

Per-account filenames are `observability_assessment_<ts>_<accountid>.html`, and the summary
links to them by that exact name. So: replace the account ID **inside** the HTML (fixes the
`href`) **and** rename the output file to the placeholder ID (same `<ts>`). Because both use
the same mapping, the links stay consistent. Keep timestamps — dates are not sensitive
(see "Manual Scrubbing Checklist" item 6) — and keep the summary filename unchanged (the
per-account "Back to Organization Summary" back-links point at it).

### 4. Turnkey loop

Keep the real mapping file **out of the repo** (use `/tmp`). Then:

```bash
SRC=assessment-result/<run-dir>; OUT=sample-result/<sample-dir>; MAP=/tmp/name-mappings.json
rm -rf "$OUT" && mkdir -p "$OUT"
declare -A PH=( [<realid1>]=111122223333 [<realid2>]=222233334444 ... )   # 1 entry per account
for f in "$SRC"/observability_assessment_*.html; do
  base=$(basename "$f"); aid=$(echo "$base" | grep -oE '[0-9]{12}')
  ts=$(echo "$base" | sed -E 's/observability_assessment_(.*)_[0-9]{12}\.html/\1/')
  python3 scripts/scrub-sample-report.py -i "$f" \
    -o "$OUT/observability_assessment_${ts}_${PH[$aid]}.html" -a "$aid" --names-file "$MAP"
done
SUM=$(basename "$SRC"/organization_summary_*.html)
python3 scripts/scrub-sample-report.py -i "$SRC/$SUM" -o "$OUT/$SUM" -a <mgmt-id> --names-file "$MAP"
```

### 5. Resource names the regex won't catch

The script auto-handles resource IDs, ARNs, and UUIDs, but **custom resource names** need
explicit `--names-file` entries. Watch for (examples use generic placeholders — substitute
what your run actually contains):

- CloudFormation **stack names with an alias/codename suffix** — e.g. a public base name plus
  an internal suffix like `<BaseStack>-<alias>`. Map it to strip the suffix
  (`<BaseStack>-<alias>` → `<BaseStack>`); substring replacement then also fixes derived log
  groups like `...-cdk-deployment`.
- **Custom S3 buckets** — e.g. `my-app-bucket-<label>-<codename>` → `amzn-s3-demo-bucket`.
- **Tool stacks** — a stack named after a third-party tool (e.g. a security scanner):
  `<Tool>AssessmentStack`, `<tool>findingsbucket`. Map the bare token both cased
  (`<Tool>` → `ExampleSecurity`, `<tool>` → `examplesecurity`).

**Keep** genuinely public names — standard AWS workshop / sample-app resource names (e.g.
public pet-store demo app components) are safe and aid teaching. Only scrub the
customer/alias-specific portions layered on top of them.

Mapping-order gotchas (the script applies `--names-file` **longest-first**):
- Put full compound strings (`my-app-bucket-<label>-<codename>`) before their shorter
  prefixes (`my-app-bucket`).
- Give a longer explicit entry (`<tool>2` → `ExampleSecurity2`) if a bare-token rule
  (`<tool>` → `examplesecurity`) would otherwise produce an ugly label like `examplesecurity2`.
- Short hex fragments inside UUIDs/CSS colors (e.g. a 4-char hex like `abc4` inside
  `...-4133-abc4-43d8...`) are false positives — the UUID scrubber rewrites those, so ignore.

### 6. Org-scan verification (do all of these)

```bash
OUT=sample-result/<sample-dir>
# a) no real account IDs remain (list your run's real IDs)
grep -rohcE '<realid1>|<realid2>|...' "$OUT" | paste -sd+ | bc          # expect 0
# b) no alias/codename/tool tokens — fill in the tokens specific to YOUR run
#    (user aliases, team/project codenames, custom bucket prefixes, tool names)
grep -rohiE '<alias>|<codename>|<custom-prefix>|<tool>|@amazon\.com' "$OUT" | sort -u   # empty
# c) only placeholder 12-digit numbers remain
grep -rohE '\b[0-9]{12}\b' "$OUT" | sort -u
# d) cross-link integrity: every summary->account link resolves, and back-links resolve
SUM=$(ls "$OUT"/organization_summary_*.html)
for h in $(grep -oE 'observability_assessment_[0-9_]+\.html' "$SUM" | sort -u); do [ -f "$OUT/$h" ] || echo "MISSING $h"; done
```

> **Do not paste real resource, account, or alias names into this guide or any committed
> file.** Keep the real→placeholder mapping only in `/tmp`. Use generic placeholders
> (`<alias>`, `<codename>`, `<tool>`) when documenting patterns here.

### 7. `.gitignore` blocks new sample folders

`sample-result/*` excludes everything except the allow-listed sample. A new org-sample
folder needs its own negation, e.g. `!sample-result/org-scan-sample/`. Verify with
`git check-ignore sample-result/<sample-dir>/<file>` (no output = trackable).

## What NOT to Scrub

- **Service names**: `Amazon CloudWatch`, `AWS X-Ray`, etc. are public.
- **Region names**: `us-west-2` is fine and expected.
- **API actions**: `logs:DescribeLogGroups`, etc. are public.
- **Metric/count values**: Total log groups, alarm counts, resource counts — keep these.
- **Assessment scores and maturity levels**: These demonstrate the tool's output.
- **AWS service log group prefixes**: `/aws/lambda/`, `/aws/eks/`, etc. are public patterns.
- **Generic resource type suffixes**: `-LogGroup`, `-cluster`, `-pipeline` are fine.

## References

- [AWS CLI Example Standards](https://docs.aws.amazon.com/cli/latest/userguide/welcome-examples.html) — `111122223333` convention
- [AWS Documentation Conventions](https://docs.aws.amazon.com/general/latest/gr/docconventions.html) — placeholder formatting
- [aws-samples contribution guide](https://github.com/aws-samples/.github/blob/main/CONTRIBUTING.md) — public repo standards
- Commit `3d21ebb` in this repo — the original scrub that established the patterns used here
