from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from src.deployment.environment_guardrail import (
    NetworkGuardrailPolicy,
    OpenStackGuardrail,
)


def make_policy(allowed_subnets):
    return NetworkGuardrailPolicy(
        version=1,
        target_host="attacker",
        default_effect="deny",
        allowed_subnets=allowed_subnets,
    )


def make_connection():
    conn = Mock()
    conn.network.create_security_group.return_value = (
        SimpleNamespace(id="guardrail-sg")
    )
    conn.network.security_group_rules.return_value = [
        SimpleNamespace(id="default-ipv4"),
        SimpleNamespace(id="default-ipv6"),
    ]
    return conn


def test_create_group_replaces_default_rules():
    conn = make_connection()
    guardrail = OpenStackGuardrail(conn)

    group_id = guardrail.create_security_group(
        make_policy(["192.168.200.0/24"]),
        name="experiment-1-guardrail",
    )

    assert group_id == "guardrail-sg"

    conn.network.security_group_rules.assert_called_once_with(
        security_group_id="guardrail-sg",
    )

    assert (
        conn.network.delete_security_group_rule.call_args_list
        == [
            call("default-ipv4"),
            call("default-ipv6"),
        ]
    )

    conn.network.create_security_group_rule.assert_called_once_with(
        security_group_id="guardrail-sg",
        direction="egress",
        ether_type="IPv4",
        remote_ip_prefix="192.168.200.0/24",
    )


def test_empty_allowlist_adds_no_rules():
    conn = make_connection()
    guardrail = OpenStackGuardrail(conn)

    guardrail.create_security_group(
        make_policy([]),
        name="experiment-2-guardrail",
    )

    assert conn.network.delete_security_group_rule.call_count == 2
    conn.network.create_security_group_rule.assert_not_called()


def test_rule_creation_failure_cleans_up_group():
    conn = make_connection()
    conn.network.create_security_group_rule.side_effect = (
        RuntimeError("Rule creation failed")
    )
    guardrail = OpenStackGuardrail(conn)

    with pytest.raises(RuntimeError, match="Rule creation failed"):
        guardrail.create_security_group(
            make_policy(["192.168.200.0/24"]),
            name="experiment-3-guardrail",
        )

    conn.network.delete_security_group.assert_called_once_with(
        "guardrail-sg",
    )


def test_cleanup_failure_preserves_original_error():
    conn = make_connection()
    conn.network.create_security_group_rule.side_effect = (
        RuntimeError("Rule creation failed")
    )
    conn.network.delete_security_group.side_effect = (
        RuntimeError("Cleanup failed")
    )
    guardrail = OpenStackGuardrail(conn)

    with pytest.raises(RuntimeError, match="Rule creation failed"):
        guardrail.create_security_group(
            make_policy(["192.168.200.0/24"]),
            name="experiment-4-guardrail",
        )
def make_port(groups, secure=True):
    return SimpleNamespace(
        is_port_security_enabled=secure,
        security_group_ids=groups,
    )


def test_attach_replaces_existing_groups():
    conn = make_connection()
    conn.network.get_port.return_value = make_port(["original-sg"])

    state = OpenStackGuardrail(conn).attach(
        "attacker-port",
        "guardrail-sg",
    )

    assert state == {
        "port_id": "attacker-port",
        "original_groups": ["original-sg"],
        "guardrail_group_id": "guardrail-sg",
    }

    conn.network.update_port.assert_called_once_with(
        "attacker-port",
        security_group_ids=["guardrail-sg"],
    )


def test_attach_rejects_disabled_port_security():
    conn = make_connection()
    conn.network.get_port.return_value = make_port(
        ["original-sg"],
        secure=False,
    )

    with pytest.raises(ValueError, match="Port security"):
        OpenStackGuardrail(conn).attach(
            "attacker-port",
            "guardrail-sg",
        )

    conn.network.update_port.assert_not_called()


def test_verify_attachment():
    conn = make_connection()
    conn.network.get_port.return_value = make_port(["guardrail-sg"])

    OpenStackGuardrail(conn).verify_attachment({
        "port_id": "attacker-port",
        "guardrail_group_id": "guardrail-sg",
    })


def test_verify_rejects_additional_group():
    conn = make_connection()
    conn.network.get_port.return_value = make_port(
        ["guardrail-sg", "unrestricted-sg"]
    )

    with pytest.raises(RuntimeError, match="exactly"):
        OpenStackGuardrail(conn).verify_attachment({
            "port_id": "attacker-port",
            "guardrail_group_id": "guardrail-sg",
        })


def test_restore_original_groups():
    conn = make_connection()
    conn.network.get_port.return_value = make_port(["guardrail-sg"])

    OpenStackGuardrail(conn).restore({
        "port_id": "attacker-port",
        "original_groups": ["original-sg"],
        "guardrail_group_id": "guardrail-sg",
    })

    conn.network.update_port.assert_called_once_with(
        "attacker-port",
        security_group_ids=["original-sg"],
    )


def test_restore_refuses_unexpected_changes():
    conn = make_connection()
    conn.network.get_port.return_value = make_port(["another-sg"])

    with pytest.raises(RuntimeError, match="changed unexpectedly"):
        OpenStackGuardrail(conn).restore({
            "port_id": "attacker-port",
            "original_groups": ["original-sg"],
            "guardrail_group_id": "guardrail-sg",
        })

    conn.network.update_port.assert_not_called()