import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.deployment.environment_guardrail import OpenStackGuardrail


def make_connection(groups):
    conn = Mock()
    conn.current_project_id = "test-project"
    conn.network.get_port.return_value = SimpleNamespace(
        is_port_security_enabled=True,
        security_group_ids=groups,
    )
    return conn


def recovery_state():
    return {
        "version": 1,
        "project_id": "test-project",
        "port_id": "attacker-port",
        "original_groups": ["original-sg"],
        "guardrail_group_id": "guardrail-sg",
    }


def test_state_is_saved_before_port_changes(tmp_path):
    conn = make_connection(["original-sg"])
    path = tmp_path / "state.json"

    def update_port(port_id, **kwargs):
        saved = json.loads(path.read_text())
        assert saved["original_groups"] == ["original-sg"]
        assert port_id == "attacker-port"

        conn.network.get_port.return_value = SimpleNamespace(
            is_port_security_enabled=True,
            security_group_ids=kwargs["security_group_ids"],
        )

    conn.network.update_port.side_effect = update_port

    OpenStackGuardrail(conn).attach_persisted(
        "attacker-port",
        "guardrail-sg",
        path,
    )

    assert json.loads(path.read_text()) == recovery_state()


def test_existing_state_is_not_overwritten(tmp_path):
    conn = make_connection(["original-sg"])
    path = tmp_path / "state.json"
    path.write_text("existing recovery data")

    with pytest.raises(FileExistsError):
        OpenStackGuardrail(conn).attach_persisted(
            "attacker-port",
            "guardrail-sg",
            path,
        )

    assert path.read_text() == "existing recovery data"
    conn.network.update_port.assert_not_called()


def test_failed_attachment_keeps_recovery_state(tmp_path):
    conn = make_connection(["original-sg"])
    conn.network.update_port.side_effect = RuntimeError(
        "API connection failed"
    )
    path = tmp_path / "state.json"

    with pytest.raises(RuntimeError, match="API connection failed"):
        OpenStackGuardrail(conn).attach_persisted(
            "attacker-port",
            "guardrail-sg",
            path,
        )

    assert json.loads(path.read_text()) == recovery_state()


def test_restore_removes_state_after_success(tmp_path):
    conn = make_connection(["guardrail-sg"])
    path = tmp_path / "state.json"
    path.write_text(json.dumps(recovery_state()))

    def update_port(port_id, **kwargs):
        conn.network.get_port.return_value = SimpleNamespace(
            is_port_security_enabled=True,
            security_group_ids=kwargs["security_group_ids"],
        )

    conn.network.update_port.side_effect = update_port

    OpenStackGuardrail(conn).restore_persisted(path)

    conn.network.update_port.assert_called_once_with(
        "attacker-port",
        security_group_ids=["original-sg"],
    )
    conn.network.delete_security_group.assert_called_once_with(
        "guardrail-sg",
        ignore_missing=True,
    )
    assert not path.exists()


def test_wrong_project_cannot_restore(tmp_path):
    conn = make_connection(["guardrail-sg"])
    conn.current_project_id = "another-project"

    path = tmp_path / "state.json"
    path.write_text(json.dumps(recovery_state()))

    with pytest.raises(ValueError, match="another OpenStack project"):
        OpenStackGuardrail(conn).restore_persisted(path)

    conn.network.update_port.assert_not_called()
    conn.network.delete_security_group.assert_not_called()
    assert path.exists()


def test_failed_cleanup_keeps_state_for_retry(tmp_path):
    conn = make_connection(["original-sg"])
    conn.network.delete_security_group.side_effect = RuntimeError(
        "Deletion failed"
    )

    path = tmp_path / "state.json"
    path.write_text(json.dumps(recovery_state()))

    with pytest.raises(RuntimeError, match="Deletion failed"):
        OpenStackGuardrail(conn).restore_persisted(path)

    assert path.exists()