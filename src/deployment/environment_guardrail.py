import json
import logging
import os
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, field_validator


logger = logging.getLogger(__name__)


class NetworkGuardrailPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    target_host: str
    default_effect: Literal["deny"]
    allowed_subnets: list[str]

    @field_validator("target_host")
    @classmethod
    def validate_target_host(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("target_host must not be empty")
        return value

    @field_validator("allowed_subnets")
    @classmethod
    def validate_subnets(cls, values: list[str]) -> list[str]:
        networks = set()

        for value in values:
            network = ip_network(value, strict=True)
            if network.prefixlen == 0:
                raise ValueError(
                    "Unrestricted /0 destinations are not supported"
                )
            networks.add(str(network))

        return sorted(networks)

    @classmethod
    def load(cls, path: str | Path) -> "NetworkGuardrailPolicy":
        with Path(path).open(encoding="utf-8") as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ValueError("Policy must be a YAML mapping")

        return cls.model_validate(data)


def build_egress_rules(
    policy: NetworkGuardrailPolicy,
) -> list[dict[str, str]]:
    """Permit all IP protocols to explicitly allowed destinations."""
    return [
        {
            "direction": "egress",
            "ether_type": (
                "IPv4" if ip_network(cidr).version == 4 else "IPv6"
            ),
            "remote_ip_prefix": cidr,
        }
        for cidr in policy.allowed_subnets
    ]


def build_infrastructure_rules(
    management_ip: str,
    c2_ip: str,
) -> list[dict]:
    """Allow management SSH and outgoing C2 communication."""

    def host_prefix(value: str) -> tuple[str, str]:
        address = ip_address(value)
        prefix_length = 32 if address.version == 4 else 128
        return (
            f"{address}/{prefix_length}",
            "IPv4" if address.version == 4 else "IPv6",
        )

    management_prefix, management_type = host_prefix(management_ip)
    c2_prefix, c2_type = host_prefix(c2_ip)

    return [
        {
            "direction": "ingress",
            "ether_type": management_type,
            "protocol": "tcp",
            "port_range_min": 22,
            "port_range_max": 22,
            "remote_ip_prefix": management_prefix,
        },
        {
            "direction": "egress",
            "ether_type": c2_type,
            "protocol": "tcp",
            "port_range_min": 8888,
            "port_range_max": 8888,
            "remote_ip_prefix": c2_prefix,
        },
    ]


class OpenStackGuardrail:
    def __init__(self, conn):
        self.conn = conn

    def create_security_group(
        self,
        policy: NetworkGuardrailPolicy,
        name: str,
        *,
        management_ip: str | None = None,
        c2_ip: str | None = None,
    ) -> str:
        rules = build_egress_rules(policy)

        if (management_ip is None) != (c2_ip is None):
            raise ValueError("Provide both management_ip and c2_ip")

        if management_ip is not None:
            rules.extend(
                build_infrastructure_rules(management_ip, c2_ip)
            )

        group = self.conn.network.create_security_group(
            name=name,
            description="MHBench network guardrail",
        )

        try:
            # Remove only this new group's automatically created rules.
            default_rules = list(
                self.conn.network.security_group_rules(
                    security_group_id=group.id,
                )
            )

            for rule in default_rules:
                self.conn.network.delete_security_group_rule(rule.id)

            for rule in rules:
                self.conn.network.create_security_group_rule(
                    security_group_id=group.id,
                    **rule,
                )

        except Exception:
            try:
                self.conn.network.delete_security_group(group.id)
            except Exception:
                logger.exception(
                    "Could not clean up guardrail group %s",
                    group.id,
                )
            raise

        return group.id

    @staticmethod
    def _rule_signature(rule) -> tuple:
        def get(field):
            if isinstance(rule, dict):
                return rule.get(field)
            return getattr(rule, field, None)

        prefix = get("remote_ip_prefix")
        if prefix:
            prefix = str(ip_network(prefix, strict=False))

        protocol = get("protocol")
        if protocol is not None:
            protocol = str(protocol).lower()
            protocol = {
                "6": "tcp",
                "17": "udp",
                "1": "icmp",
                "58": "ipv6-icmp",
            }.get(protocol, protocol)

        return (
            get("direction"),
            get("ether_type"),
            protocol,
            get("port_range_min"),
            get("port_range_max"),
            prefix,
            get("remote_group_id"),
            get("remote_address_group_id"),
        )

    def verify_rules(
        self,
        group_id: str,
        policy: NetworkGuardrailPolicy,
        *,
        management_ip: str,
        c2_ip: str,
    ) -> None:
        expected_rules = [
            *build_egress_rules(policy),
            *build_infrastructure_rules(management_ip, c2_ip),
        ]

        expected = {
            self._rule_signature(rule) for rule in expected_rules
        }

        actual = {
            self._rule_signature(rule)
            for rule in self.conn.network.security_group_rules(
                security_group_id=group_id,
            )
        }

        if actual != expected:
            raise RuntimeError(
                "Security Group rules do not match the guardrail policy"
            )

    def attach(self, port_id: str, group_id: str) -> dict:
        """In-memory helper; deployment uses attach_persisted instead."""
        port = self.conn.network.get_port(port_id)

        if not port.is_port_security_enabled:
            raise ValueError("Port security must be enabled")

        original_groups = list(port.security_group_ids or [])

        if group_id in original_groups:
            raise ValueError("Guardrail group is already attached")

        state = {
            "port_id": port_id,
            "original_groups": original_groups,
            "guardrail_group_id": group_id,
        }

        self.conn.network.update_port(
            port_id,
            security_group_ids=[group_id],
        )

        return state

    def verify_attachment(self, state: dict) -> None:
        port = self.conn.network.get_port(state["port_id"])

        if not port.is_port_security_enabled:
            raise RuntimeError("Port security is disabled")

        if set(port.security_group_ids or []) != {
            state["guardrail_group_id"]
        }:
            raise RuntimeError(
                "Port does not have exactly the guardrail group"
            )

    def restore(self, state: dict) -> None:
        port = self.conn.network.get_port(state["port_id"])
        current = set(port.security_group_ids or [])
        original = set(state["original_groups"])
        guardrail = {state["guardrail_group_id"]}

        if current == original:
            return

        if current != guardrail:
            raise RuntimeError(
                "Port groups changed unexpectedly; refusing to overwrite"
            )

        self.conn.network.update_port(
            state["port_id"],
            security_group_ids=state["original_groups"],
        )

    def attach_persisted(
        self,
        port_id: str,
        group_id: str,
        state_path: str | Path,
    ) -> dict:
        path = Path(state_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        port = self.conn.network.get_port(port_id)

        if not port.is_port_security_enabled:
            raise ValueError("Port security must be enabled")

        original_groups = list(port.security_group_ids or [])

        if group_id in original_groups:
            raise ValueError("Guardrail group is already attached")

        state = {
            "version": 1,
            "project_id": self.conn.current_project_id,
            "port_id": port_id,
            "original_groups": original_groups,
            "guardrail_group_id": group_id,
        }

        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(state, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        # Retain state on API failure: the request might have succeeded.
        self.conn.network.update_port(
            port_id,
            security_group_ids=[group_id],
        )

        self.verify_attachment(state)
        return state

    def restore_persisted(
        self,
        state_path: str | Path,
    ) -> None:
        path = Path(state_path)

        with path.open(encoding="utf-8") as file:
            state = json.load(file)

        if state.get("version") != 1:
            raise ValueError("Unsupported recovery state version")

        if state["project_id"] != self.conn.current_project_id:
            raise ValueError(
                "Recovery state belongs to another OpenStack project"
            )

        self.restore(state)

        port = self.conn.network.get_port(state["port_id"])
        if set(port.security_group_ids or []) != set(
            state["original_groups"]
        ):
            raise RuntimeError(
                "Original security groups have not been restored"
            )

        self.conn.network.delete_security_group(
            state["guardrail_group_id"],
            ignore_missing=True,
        )

        path.unlink()