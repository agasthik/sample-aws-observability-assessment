# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from ..models import DiscoveryCheck
from .check_specs import CHECK_SPECS


class CatalogMixin:
    """Register the built-in discovery checks and any local additions."""

    def add_discovery_check(self, name: str, category: str, command: str) -> int:
        """Add a discovery check, combining duplicates with comma-separated categories"""
        # Check if this check already exists (same name and command)
        existing_check = next(
            (
                c
                for c in self.results.discovery_checks
                if c.name == name and c.command == command
            ),
            None,
        )

        if existing_check:
            # Add category to existing check if not already present
            categories = existing_check.category.split(", ")
            if category not in categories:
                categories.append(category)
                existing_check.category = ", ".join(sorted(categories))
            return existing_check.id
        else:
            # Create new check
            self.discovery_check_counter += 1
            check = DiscoveryCheck(
                id=self.discovery_check_counter,
                name=name,
                category=category,
                command=command,
            )
            self.results.discovery_checks.append(check)
            return self.discovery_check_counter

    def setup_discovery_checks(self):
        """Setup all discovery checks across all categories"""
        print("Setting up discovery checks...")

        # Get largest log groups by compute type for later use
        print("Identifying largest log groups by compute type...")
        self.largest_log_groups = self.get_largest_log_groups_by_compute_type()
        if self.largest_log_groups is None:
            print(
                "   [WARN] Could not list log groups; checks that depend on them will be marked unavailable"
            )
        else:
            total_groups = sum(
                len(groups) for groups in self.largest_log_groups.values()
            )
            print(
                f"   Found {total_groups} largest log groups: EC2({len(self.largest_log_groups['EC2'])}), ECS({len(self.largest_log_groups['ECS'])}), Lambda({len(self.largest_log_groups['Lambda'])}), EKS({len(self.largest_log_groups['EKS'])})"
            )

        current = self.results.discovery_checks
        if current:
            # Repeated setup preserves results already collected. A custom check
            # registered before setup would occupy a frozen built-in ID.
            built_ins = current[: len(CHECK_SPECS)]
            if len(built_ins) != len(CHECK_SPECS) or any(
                (check.id, check.name, check.category, check.command)
                != (spec.id, spec.name, spec.category, spec.command)
                for check, spec in zip(built_ins, CHECK_SPECS)
            ):
                raise ValueError("Discovery checks must be set up before custom checks")
            return

        current.extend(
            DiscoveryCheck(
                id=spec.id,
                name=spec.name,
                category=spec.category,
                command=spec.command,
            )
            for spec in CHECK_SPECS
        )
        self.discovery_check_counter = CHECK_SPECS[-1].id
