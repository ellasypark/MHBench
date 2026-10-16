import json
import logging
from pathlib import Path
from uuid import uuid4

from src.deployment.environment_guardrail import (
    NetworkGuardrailPolicy,
    OpenStackGuardrail,
)


logger = logging.getLogger(__name__)


class GuardrailLifecycle:
    """Guardrail integration for generated MHBench environments."""

    def __init__(self, conn, config):
        self.conn = conn
        self.config = config
        self.guardrail = OpenStackGuardrail(conn)

    @property
    def state_path(self) -> Path:
        return (
            self.config.network_guardrail.state_dir
            / f"{self.conn.current_project_id}-attacker.json"
        )

    def validate_policy(self) -> NetworkGuardrailPolicy:
        policy = NetworkGuardrailPolicy.load(
            self.config.network_guardrail.policy_path
        )

        if policy.target_host != "attacker_host":
            raise ValueError(
                "Generated-environment integration currently supports "
                "target_host: attacker_host only"
            )

        return policy

    def _find_attacker_port(self, policy):
        project_id = self.conn.current_project_id

        servers = [
            server
            for server in self.conn.compute.servers(
                name=policy.target_host,
                project_id=project_id,
            )
            if server.name == policy.target_host
        ]

        if len(servers) != 1:
            raise RuntimeError(
                "Expected exactly one attacker_host in the current project"
            )

        networks = [
            network
            for network in self.conn.network.networks(
                name="attacker_network",
                project_id=project_id,
            )
            if network.name == "attacker_network"
        ]

        if len(networks) != 1:
            raise RuntimeError(
                "Expected exactly one attacker_network"
            )

        ports = list(
            self.conn.network.ports(device_id=servers[0].id)
        )

        if (
            len(ports) != 1
            or ports[0].network_id != networks[0].id
        ):
            raise RuntimeError(
                "Expected one attacker port on attacker_network"
            )

        port = ports[0]

        if not port.is_port_security_enabled:
            raise RuntimeError("Attacker port security is disabled")

        return port

    def apply(self) -> str | None:
        if self.state_path.exists():
            raise RuntimeError(
                "Guardrail recovery state already exists. "
                "Restore it before starting another deployment."
            )

        if not self.config.network_guardrail.enabled:
            return None

        policy = self.validate_policy()
        port = self._find_attacker_port(policy)

        group_id = self.guardrail.create_security_group(
            policy,
            name=f"mhbench-guardrail-{uuid4().hex}",
            management_ip="192.168.198.14",
            c2_ip=self.config.external_ip,
        )

        try:
            self.guardrail.verify_rules(
                group_id,
                policy,
                management_ip="192.168.198.14",
                c2_ip=self.config.external_ip,
            )

            self.guardrail.attach_persisted(
                port.id,
                group_id,
                self.state_path,
            )

        except Exception:
            # Preserve resources if attachment recovery may be needed.
            if not self.state_path.exists():
                try:
                    self.conn.network.delete_security_group(
                        group_id,
                        ignore_missing=True,
                    )
                except Exception:
                    logger.exception(
                        "Could not delete guardrail group %s",
                        group_id,
                    )
            raise

        return group_id

    def verify(self) -> None:
        if not self.config.network_guardrail.enabled:
            if self.state_path.exists():
                raise RuntimeError(
                    "Guardrail is configured OFF but recovery state exists. "
                    "Restore it explicitly."
                )
            return

        if not self.state_path.exists():
            raise RuntimeError(
                "Guardrail is enabled but has not been applied"
            )

        with self.state_path.open(encoding="utf-8") as file:
            state = json.load(file)

        if state.get("version") != 1:
            raise ValueError("Unsupported recovery state version")

        if state["project_id"] != self.conn.current_project_id:
            raise ValueError("Guardrail state belongs to another project")

        policy = self.validate_policy()
        port = self._find_attacker_port(policy)

        if port.id != state["port_id"]:
            raise RuntimeError(
                "Current attacker port differs from recovery state"
            )

        self.guardrail.verify_rules(
            state["guardrail_group_id"],
            policy,
            management_ip="192.168.198.14",
            c2_ip=self.config.external_ip,
        )
        self.guardrail.verify_attachment(state)

    def restore(self) -> bool:
        # Restore even if enabled has since been changed to false.
        if not self.state_path.exists():
            return False

        self.guardrail.restore_persisted(self.state_path)
        return True