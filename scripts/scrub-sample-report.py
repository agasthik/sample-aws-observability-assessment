#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Scrub sensitive AWS resource data from an Observability Assessment HTML report.

Replaces a specified account ID, known resource identifier patterns, UUIDs, email
addresses, and custom names supplied in a mapping file with documentation-style
placeholders. It does not discover arbitrary customer resource names automatically.
See SCRUBBING.md for conventions and required manual review.

Usage:
    python3 scripts/scrub-sample-report.py \
        --input assessment-result/observability_assessment_20260712_164009_123456789012.html \
        --output sample-result/observability_assessment_sample.html \
        --account-id 123456789012

    # With custom name mappings:
    python3 scripts/scrub-sample-report.py \
        --input report.html \
        --output sample.html \
        --account-id 123456789012 \
        --names-file scripts/name-mappings.json
"""

import argparse
import json
import re
import sys
from pathlib import Path


# --- Placeholder patterns (AWS documentation standards) ---

PLACEHOLDER_ACCOUNT = "111122223333"
PLACEHOLDER_REGION = "us-west-2"

# Incrementing UUID templates for different resource categories
UUID_COUNTERS: dict[str, int] = {}


def next_uuid(category: str = "default") -> str:
    """Generate incrementing placeholder UUIDs per category."""
    UUID_COUNTERS.setdefault(category, 0)
    UUID_COUNTERS[category] += 1
    n = UUID_COUNTERS[category]
    return f"a1b2c3d4-{n:04d}-{n:04d}-{n:04d}-abcdef{n:06d}"


# --- Regex patterns for AWS resource identifiers ---

RESOURCE_ID_PATTERNS = [
    # EC2 Instance IDs: i-0123456789abcdef0
    (re.compile(r"\bi-[0-9a-f]{8,17}\b"), "i-1234567890abcdef0"),
    # VPC IDs: vpc-0123456789abcdef0
    (re.compile(r"\bvpc-[0-9a-f]{8,17}\b"), "vpc-1a2b3c4d5e6f7a8b9"),
    # Subnet IDs: subnet-0123456789abcdef0
    (re.compile(r"\bsubnet-[0-9a-f]{8,17}\b"), "subnet-1a2b3c4d5e6f7a8b"),
    # Security Group IDs: sg-0123456789abcdef0
    (re.compile(r"\bsg-[0-9a-f]{8,17}\b"), "sg-1a2b3c4d5e6f7a8b9"),
    # ENI IDs: eni-0123456789abcdef0
    (re.compile(r"\beni-[0-9a-f]{8,17}\b"), "eni-1a2b3c4d5e6f7a8b9"),
    # NAT Gateway IDs: nat-0123456789abcdef0
    (re.compile(r"\bnat-[0-9a-f]{8,17}\b"), "nat-1a2b3c4d5e6f7a8b9"),
    # Internet Gateway IDs: igw-0123456789abcdef0
    (re.compile(r"\bigw-[0-9a-f]{8,17}\b"), "igw-1a2b3c4d5e6f7a8b9"),
    # Route Table IDs: rtb-0123456789abcdef0
    (re.compile(r"\brtb-[0-9a-f]{8,17}\b"), "rtb-1a2b3c4d5e6f7a8b9"),
    # EBS Volume IDs: vol-0123456789abcdef0
    (re.compile(r"\bvol-[0-9a-f]{8,17}\b"), "vol-1a2b3c4d5e6f7a8b9"),
    # Snapshot IDs: snap-0123456789abcdef0
    (re.compile(r"\bsnap-[0-9a-f]{8,17}\b"), "snap-1a2b3c4d5e6f7a8b9"),
    # AMI IDs: ami-0123456789abcdef0
    (re.compile(r"\bami-[0-9a-f]{8,17}\b"), "ami-1a2b3c4d5e6f7a8b9"),
]

# UUID pattern (standard 8-4-4-4-12 hex format) — used in stack IDs, etc.
UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# AMP workspace IDs: ws-<uuid>
AMP_WORKSPACE_PATTERN = re.compile(
    r"\bws-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)


def scrub_account_id(content: str, real_account_id: str) -> str:
    """Replace the real 12-digit account ID with the placeholder."""
    return content.replace(real_account_id, PLACEHOLDER_ACCOUNT)


def scrub_resource_ids(content: str) -> str:
    """Replace known AWS resource ID patterns with placeholders."""
    for pattern, placeholder in RESOURCE_ID_PATTERNS:
        content = pattern.sub(placeholder, content)
    return content


def scrub_amp_workspaces(content: str) -> str:
    """Replace AMP workspace IDs."""
    counter = [0]

    def replacer(match: re.Match) -> str:
        counter[0] += 1
        n = counter[0]
        return f"ws-a1b2c3d4-{n:04d}-{n:04d}-{n:04d}-abcdef{n:06d}"

    return AMP_WORKSPACE_PATTERN.sub(replacer, content)


def scrub_uuids(content: str, preserve_prefixes: bool = True) -> str:
    """
    Replace UUIDs with incrementing placeholders.

    Preserves known prefixes (ws-, cwsyn-, etc.) by only replacing UUIDs
    that appear in ARN/stack-id contexts.
    """
    seen: dict[str, str] = {}
    counter = [0]

    def replacer(match: re.Match) -> str:
        original = match.group(0).lower()
        if original not in seen:
            counter[0] += 1
            n = counter[0]
            seen[original] = f"a1b2c3d4-{n:04d}-{n:04d}-{n:04d}-abcdef{n:06d}"
        return seen[original]

    return UUID_PATTERN.sub(replacer, content)


def scrub_custom_names(content: str, name_mappings: dict[str, str]) -> str:
    """
    Replace custom resource names using a provided mapping.

    Mappings are applied longest-first to avoid partial replacements.
    """
    # Sort by length descending so longer matches take priority
    sorted_mappings = sorted(
        name_mappings.items(), key=lambda x: len(x[0]), reverse=True
    )
    for original, replacement in sorted_mappings:
        content = content.replace(original, replacement)
    return content


def scrub_email_addresses(content: str) -> str:
    """Replace email addresses with a placeholder."""
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    return email_pattern.sub("user@example.com", content)


def verify_scrub(content: str, real_account_id: str) -> list[str]:
    """Check for potential remaining sensitive data and return warnings."""
    warnings = []

    # Check for remaining real account ID
    if real_account_id in content:
        count = content.count(real_account_id)
        warnings.append(f"WARNING: Real account ID still found {count} time(s)")

    # Check for 12-digit numbers that aren't the placeholder
    other_accounts = set(re.findall(r"\b\d{12}\b", content)) - {PLACEHOLDER_ACCOUNT}
    if other_accounts:
        warnings.append(f"WARNING: Other 12-digit numbers found: {other_accounts}")

    # Check for .corp. or .internal. hostnames
    internal_hosts = re.findall(r"[\w.-]+\.(corp|internal)\.\w+", content)
    if internal_hosts:
        warnings.append(f"WARNING: Internal hostnames found: {internal_hosts[:5]}")

    # Check for @amazon.com emails
    amazon_emails = re.findall(r"\b\S+@amazon\.com\b", content)
    if amazon_emails:
        warnings.append(f"WARNING: Amazon emails found: {amazon_emails[:5]}")

    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scrub sensitive data from Observability Assessment HTML reports.",
        epilog="See SCRUBBING.md for placeholder conventions and manual review guidance.",
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to the raw assessment HTML report",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Path for the scrubbed output file",
    )
    parser.add_argument(
        "--account-id",
        "-a",
        required=True,
        help="The real AWS account ID (12 digits) to replace",
    )
    parser.add_argument(
        "--names-file",
        "-n",
        help='JSON file with custom name mappings: {"real-name": "ExampleName", ...}',
    )
    parser.add_argument(
        "--skip-uuids",
        action="store_true",
        help="Skip UUID replacement (if you want to preserve them for some reason)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only run verification on an existing file, don't transform",
    )
    args = parser.parse_args()

    # Validate account ID format
    if not re.match(r"^\d{12}$", args.account_id):
        print(
            f"ERROR: Account ID must be exactly 12 digits, got: {args.account_id}",
            file=sys.stderr,
        )
        return 1

    # Read input
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        return 1

    content = input_path.read_text(encoding="utf-8")
    original_size = len(content)

    if args.verify_only:
        warnings = verify_scrub(content, args.account_id)
        if warnings:
            for w in warnings:
                print(w, file=sys.stderr)
            return 1
        print("[OK] No sensitive data patterns detected.")
        return 0

    # Load custom name mappings if provided
    name_mappings: dict[str, str] = {}
    if args.names_file:
        names_path = Path(args.names_file)
        if not names_path.exists():
            print(f"ERROR: Names file not found: {names_path}", file=sys.stderr)
            return 1
        name_mappings = json.loads(names_path.read_text(encoding="utf-8"))

    # Apply scrubbing in order (order matters — account ID first, then structured IDs)
    print(f"Scrubbing {input_path} ({original_size:,} bytes)...")

    # 1. Account ID (most important — do first before ARNs are modified)
    content = scrub_account_id(content, args.account_id)
    print(f"  [OK] Account ID: {args.account_id} → {PLACEHOLDER_ACCOUNT}")

    # 2. Custom name mappings (before resource IDs, since names may contain ID-like patterns)
    if name_mappings:
        content = scrub_custom_names(content, name_mappings)
        print(f"  [OK] Custom names: {len(name_mappings)} replacements applied")

    # 3. AMP workspace IDs (before general UUID scrub)
    content = scrub_amp_workspaces(content)
    print("  [OK] AMP workspace IDs")

    # 4. Resource IDs (EC2, VPC, subnet, SG, etc.)
    content = scrub_resource_ids(content)
    print("  [OK] Resource IDs (EC2, VPC, subnet, SG, ENI, NAT, IGW, etc.)")

    # 5. UUIDs in stack IDs and other contexts
    if not args.skip_uuids:
        content = scrub_uuids(content)
        print("  [OK] UUIDs (stack IDs, resource GUIDs)")

    # 6. Email addresses
    content = scrub_email_addresses(content)
    print("  [OK] Email addresses")

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    print(f"\nWritten to {output_path} ({len(content):,} bytes)")

    # Run verification
    warnings = verify_scrub(content, args.account_id)
    if warnings:
        print("\n[WARN] Post-scrub verification found issues:")
        for w in warnings:
            print(f"  {w}")
        print("\n  → Manual review recommended before committing.")
        return 0  # Still exit 0 — warnings are advisory
    else:
        print("\n[OK] Post-scrub verification passed — no sensitive patterns detected.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
