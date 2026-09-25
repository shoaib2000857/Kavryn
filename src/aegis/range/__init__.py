"""The runtime attack range (docs/IMPLEMENTATION_HANDOFF.md Change 7).

Orchestrates a case-isolated Docker-internal network, the vulnerable app
and containment proxy (neither given a published port) -- plus benign/attack
traffic helpers, telemetry normalization, and deployment provenance
tying a running deployment back to pinned source.
"""

from aegis.range.containment import ContainmentRule, read_rules, write_rules
from aegis.range.docker_cmd import DockerCommandError
from aegis.range.logs import ProxyLogsAdapter
from aegis.range.network import create_network, remove_network
from aegis.range.provenance import DeploymentProvenance
from aegis.range.service import (
    ServiceSpec,
    container_ip,
    container_logs,
    start_service,
    stop_service,
)
from aegis.range.traffic import RequestOutcome, send_get

__all__ = [
    "ContainmentRule",
    "DeploymentProvenance",
    "DockerCommandError",
    "ProxyLogsAdapter",
    "RequestOutcome",
    "ServiceSpec",
    "container_ip",
    "container_logs",
    "create_network",
    "read_rules",
    "remove_network",
    "send_get",
    "start_service",
    "stop_service",
    "write_rules",
]
