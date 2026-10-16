import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from config.config import NetworkGuardrailConfig
from src.deployment.guardrail_lifecycle import GuardrailLifecycle


def make_lifecycle(tmp_path, enabled=True):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
target_host: attacker_host
default_effect: deny
allowed_subnets:
  - "192.168.200.0/24"
""",
        encoding="utf-8",
    )

    config = SimpleNamespace(
        external_ip="192.0.2.10",
        network_guardrail=NetworkGuardrailConfig(
            enabled=enabled,
            policy_path=policy_path,
            state_dir=tmp_path / "state",
        ),
    )

    conn = Mock()
    conn.current_project_id = "test-project"

    conn.compute.servers.return_value = [
        SimpleNamespace(id="attacker-id", name="attacker_host")
    ]

    conn.network.networks.return_value = [
        SimpleNamespace(id="network-id", name="attacker_network")
    ]

    conn.network.ports.return_value = [
        SimpleNamespace(
            id="port-id",
            network_id="network-id",
            is_port_security_enabled=True,
        )
    ]

    lifecycle = GuardrailLifecycle(conn, config)
    lifecycle.guardrail = Mock()
    lifecycle.guardrail.create_security_group.return_value = (
        "guardrail-sg"
    )

    return lifecycle, conn


def test_off_makes_no_cloud_calls(tmp_path):
    lifecycle, conn = make_lifecycle(tmp_path, enabled=False)

    assert lifecycle.apply() is None

    assert conn.mock_calls == []
    assert lifecycle.guardrail.mock_calls == []


def test_on_selects_attacker_and_attaches_group(tmp_path):
    lifecycle, conn = make_lifecycle(tmp_path)

    assert lifecycle.apply() == "guardrail-sg"

    conn.compute.servers.assert_called_once_with(
        name="attacker_host",
        project_id="test-project",
    )

    conn.network.networks.assert_called_once_with(
        name="attacker_network",
        project_id="test-project",
    )

    conn.network.ports.assert_called_once_with(
        device_id="attacker-id",
    )

    lifecycle.guardrail.attach_persisted.assert_called_once_with(
        "port-id",
        "guardrail-sg",
        lifecycle.state_path,
    )

    kwargs = (
        lifecycle.guardrail.create_security_group.call_args.kwargs
    )
    assert kwargs["management_ip"] == "192.168.198.14"
    assert kwargs["c2_ip"] == "192.0.2.10"


def test_missing_attacker_changes_nothing(tmp_path):
    lifecycle, conn = make_lifecycle(tmp_path)
    conn.compute.servers.return_value = []

    with pytest.raises(RuntimeError, match="exactly one attacker_host"):
        lifecycle.apply()

    lifecycle.guardrail.create_security_group.assert_not_called()


def test_multiple_attacker_ports_are_rejected(tmp_path):
    lifecycle, conn = make_lifecycle(tmp_path)

    conn.network.ports.return_value = [
        SimpleNamespace(
            id="port-1",
            network_id="network-id",
            is_port_security_enabled=True,
        ),
        SimpleNamespace(
            id="port-2",
            network_id="another-network",
            is_port_security_enabled=True,
        ),
    ]

    with pytest.raises(RuntimeError, match="one attacker port"):
        lifecycle.apply()

    lifecycle.guardrail.create_security_group.assert_not_called()


def test_existing_recovery_state_blocks_apply(tmp_path):
    lifecycle, conn = make_lifecycle(tmp_path)
    lifecycle.state_path.parent.mkdir(parents=True)
    lifecycle.state_path.write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="recovery state"):
        lifecycle.apply()

    assert conn.mock_calls == []
    lifecycle.guardrail.create_security_group.assert_not_called()


def test_attachment_failure_preserves_recovery_resources(tmp_path):
    lifecycle, conn = make_lifecycle(tmp_path)

    def fail_after_saving(*args):
        lifecycle.state_path.parent.mkdir(parents=True)
        lifecycle.state_path.write_text(
            json.dumps({"recovery": "required"}),
            encoding="utf-8",
        )
        raise RuntimeError("Attachment failed")

    lifecycle.guardrail.attach_persisted.side_effect = (
        fail_after_saving
    )

    with pytest.raises(RuntimeError, match="Attachment failed"):
        lifecycle.apply()

    assert lifecycle.state_path.exists()
    conn.network.delete_security_group.assert_not_called()


def test_failure_before_state_creation_cleans_up_group(tmp_path):
    lifecycle, conn = make_lifecycle(tmp_path)
    lifecycle.guardrail.attach_persisted.side_effect = (
        RuntimeError("Could not save state")
    )

    with pytest.raises(RuntimeError, match="Could not save state"):
        lifecycle.apply()

    conn.network.delete_security_group.assert_called_once_with(
        "guardrail-sg",
        ignore_missing=True,
    )


def test_restore_works_even_when_setting_is_off(tmp_path):
    lifecycle, _ = make_lifecycle(tmp_path, enabled=False)
    lifecycle.state_path.parent.mkdir(parents=True)
    lifecycle.state_path.write_text("{}", encoding="utf-8")

    assert lifecycle.restore() is True

    lifecycle.guardrail.restore_persisted.assert_called_once_with(
        lifecycle.state_path,
    )


def test_restore_without_state_does_nothing(tmp_path):
    lifecycle, _ = make_lifecycle(tmp_path)

    assert lifecycle.restore() is False
    lifecycle.guardrail.restore_persisted.assert_not_called()