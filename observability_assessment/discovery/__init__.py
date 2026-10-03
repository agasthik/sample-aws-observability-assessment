# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from .alarms import AlarmsDiscoveryMixin
from .catalog import CatalogMixin
from .compute import ComputeDiscoveryMixin
from .executor import DiscoveryExecutorMixin
from .logs import LogsDiscoveryMixin
from .metrics import MetricsDiscoveryMixin
from .organization import OrganizationDiscoveryMixin
from .traces import TracesDiscoveryMixin


class DiscoveryMixin(
    CatalogMixin,
    DiscoveryExecutorMixin,
    LogsDiscoveryMixin,
    ComputeDiscoveryMixin,
    MetricsDiscoveryMixin,
    TracesDiscoveryMixin,
    AlarmsDiscoveryMixin,
    OrganizationDiscoveryMixin,
):
    """Compose the discovery catalog, executor, and service collectors."""
