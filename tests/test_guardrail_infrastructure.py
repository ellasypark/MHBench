from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.deployment.environment_guardrail import (
    NetworkGuardrailPolicy,
    OpenStackGuardrail,
    build_infrastructure_rules,
)


def test_infrastructure_rules_are_scoped_to_hosts_and_ports():
    assert build_infrastructure_rules(
        "192.168.198.14",
        "192.0.2.10",
    ) == [
        {
            "direction": "ingress",
            "ether_type": "IPv4",
            "protocol": "tcp",
            "port_range_min": 22,
            "port_range_max": 22,
            "remote_ip_prefix": "192.168.198.14/32",
        },
        {
            "direction": "egress",
            "ether_type": "IPv4",
            "protocol": "tcp",
            "port_range_min": 8888,
            "port_range_max": 8888,
            "remote_ip_prefix": "192.0.2.10/32",
        },
    ]


def test_invalid_infrastructure_ip_is_rejected():
    with pytest.raises(ValueError):
        build_infrastructure_rules(
            "192.168.198.14",
            "invalid-address",
        )


def test_group_contains_policy_and_infrastructure_rules():
    conn = Mock()
    conn.network.create_security_group.return_value = (
        SimpleNamespace(id="guardrail-sg")
    )
    conn.network.security_group_rules.return_value = []

    policy = NetworkGuardrailPolicy(
        version=1,
        target_host="attacker_host",
        default_effect="deny",
        allowed_subnets=["192.168.200.0/24"],
    )

    OpenStackGuardrail(conn).create_security_group(
        policy,
        name="test-guardrail",
        management_ip="192.168.198.14",
        c2_ip="192.0.2.10",
    )

    calls = (
        conn.network.create_security_group_rule.call_args_list
    )
    actual_rules = [item.kwargs for item in calls]

    assert len(actual_rules) == 3

    assert {
        "security_group_id": "guardrail-sg",
        "direction": "egress",
        "ether_type": "IPv4",
        "remote_ip_prefix": "192.168.200.0/24",
    } in actual_rules

    for rule in build_infrastructure_rules(
        "192.168.198.14",
        "192.0.2.10",
    ):
        assert {
            "security_group_id": "guardrail-sg",
            **rule,
        } in actual_rules


def test_missing_infrastructure_argument_changes_nothing():
    conn = Mock()

    policy = NetworkGuardrailPolicy(
        version=1,
        target_host="attacker_host",
        default_effect="deny",
        allowed_subnets=[],
    )

    with pytest.raises(ValueError, match="both"):
        OpenStackGuardrail(conn).create_security_group(
            policy,
            name="test-guardrail",
            management_ip="192.168.198.14",
        )

    conn.network.create_security_group.assert_not_called()