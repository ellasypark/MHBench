from pathlib import Path

import pytest
from pydantic import ValidationError

from config.config import Config, NetworkGuardrailConfig


def example_config():
    """Dummy values only; these tests do not contact OpenStack."""
    return {
        "elastic_config": {
            "api_key": "test-only",
            "port": 9200,
        },
        "openstack_config": {
            "ssh_key_name": "test-key",
            "ssh_key_path": "/tmp/test-key.pem",
            "project_name": "test-project",
            "openstack_username": "test-user",
            "openstack_password": "test-only",
            "openstack_region": "test-region",
            "openstack_auth_url": "https://example.invalid/v3",
        },
        "external_ip": "192.0.2.1",
        "experiment_timeout_minutes": 75,
    }


def test_guardrail_disabled_by_default():
    config = NetworkGuardrailConfig()

    assert config.enabled is False
    assert config.policy_path is None


def test_guardrail_config_accepts_policy_path():
    config = NetworkGuardrailConfig(
        enabled=True,
        policy_path="config/policies/network_guardrail.yaml",
    )

    assert config.enabled is True
    assert config.policy_path == Path(
        "config/policies/network_guardrail.yaml"
    )


def test_enabled_guardrail_requires_policy_path():
    with pytest.raises(ValidationError, match="policy_path"):
        NetworkGuardrailConfig(enabled=True)


def test_guardrail_rejects_unknown_settings():
    with pytest.raises(ValidationError):
        NetworkGuardrailConfig(enable=True)


def test_existing_config_still_loads():
    config = Config.model_validate(example_config())

    assert config.network_guardrail.enabled is False
    assert config.c2_config is None
    assert config.terraform_vars == {
        "project_name": "test-project",
        "openstack_username": "test-user",
        "openstack_password": "test-only",
        "openstack_region": "test-region",
        "openstack_auth_url": "https://example.invalid/v3",
        "perry_key_name": "test-key",
    }


def test_guardrail_loads_through_existing_json_service(tmp_path):
    import json

    from config.config_service import ConfigService

    data = example_config()
    data["network_guardrail"] = {
        "enabled": True,
        "policy_path": "config/policies/network_guardrail.yaml",
    }

    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    config = ConfigService(str(path)).get_config()

    assert config.network_guardrail.enabled is True
    assert config.network_guardrail.policy_path == Path(
        "config/policies/network_guardrail.yaml"
    )