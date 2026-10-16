from ipaddress import ip_network
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, field_validator


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
    """Build rule definitions without contacting OpenStack."""
    rules = []

    for cidr in policy.allowed_subnets:
        network = ip_network(cidr)

        rules.append(
            {
                "direction": "egress",
                "ether_type": (
                    "IPv4" if network.version == 4 else "IPv6"
                ),
                "remote_ip_prefix": str(network),
            }
        )

    return rules