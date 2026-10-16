import pytest
from pydantic import ValidationError

from src.deployment.environment_guardrail import (
    NetworkGuardrailPolicy,
    build_egress_rules,
)


def make_policy(**overrides):
    data = {
        "version": 1,
        "target_host": "attacker",
        "default_effect": "deny",
        "allowed_subnets": ["192.168.200.0/24"],
    }
    data.update(overrides)

    return NetworkGuardrailPolicy.model_validate(data)


def test_load_yaml(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
version: 1
target_host: attacker
default_effect: deny
allowed_subnets:
  - "192.168.200.0/24"
""",
        encoding="utf-8",
    )

    policy = NetworkGuardrailPolicy.load(path)

    assert policy.target_host == "attacker"
    assert policy.allowed_subnets == ["192.168.200.0/24"]


@pytest.mark.parametrize(
    "cidr",
    [
        "not-a-network",
        "192.168.200.10/24",
        "0.0.0.0/0",
        "::/0",
    ],
)
def test_reject_invalid_or_unrestricted_subnet(cidr):
    with pytest.raises(ValidationError):
        make_policy(allowed_subnets=[cidr])


def test_reject_blocklist_mode():
    with pytest.raises(ValidationError):
        make_policy(default_effect="allow")


def test_reject_unknown_fields():
    with pytest.raises(ValidationError):
        make_policy(allow_subnets=["192.168.201.0/24"])


def test_reject_empty_target_host():
    with pytest.raises(ValidationError):
        make_policy(target_host="   ")


def test_remove_duplicate_subnets():
    policy = make_policy(
        allowed_subnets=[
            "192.168.200.0/24",
            "192.168.200.0/24",
        ],
    )

    assert policy.allowed_subnets == ["192.168.200.0/24"]


def test_empty_allowlist_is_valid():
    policy = make_policy(allowed_subnets=[])

    assert policy.allowed_subnets == []


def test_reject_non_mapping_yaml(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("- invalid\n- policy\n", encoding="utf-8")

    with pytest.raises(ValueError, match="YAML mapping"):
        NetworkGuardrailPolicy.load(path)


def test_build_ipv4_egress_rule():
    policy = make_policy(
        allowed_subnets=["192.168.200.0/24"],
    )

    assert build_egress_rules(policy) == [
        {
            "direction": "egress",
            "ether_type": "IPv4",
            "remote_ip_prefix": "192.168.200.0/24",
        }
    ]


def test_build_ipv6_egress_rule():
    policy = make_policy(
        allowed_subnets=["fd00:200::/64"],
    )

    assert build_egress_rules(policy) == [
        {
            "direction": "egress",
            "ether_type": "IPv6",
            "remote_ip_prefix": "fd00:200::/64",
        }
    ]


def test_empty_allowlist_generates_no_rules():
    policy = make_policy(allowed_subnets=[])

    assert build_egress_rules(policy) == []