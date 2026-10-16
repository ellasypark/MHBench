import importlib
import json
import os
from datetime import datetime
from types import SimpleNamespace

import click
import openstack

from ansible.ansible_runner import AnsibleRunner
from config.config_service import ConfigService
from src.deployment.guardrail_lifecycle import GuardrailLifecycle
from src.env_gen_deployer import EnvGenDeployer
from src.models.network import NetworkTopology
from src.terraform_deployer import TerraformDeployer


env_module = importlib.import_module(
    "src.environments.terraform.specifications"
)


def create_openstack_connection(openstack_cfg):
    return openstack.connect(
        auth_url=openstack_cfg.openstack_auth_url,
        username=openstack_cfg.openstack_username,
        password=openstack_cfg.openstack_password,
        project_name=openstack_cfg.project_name,
        region_name=openstack_cfg.openstack_region,
        user_domain_name="Default",
        project_domain_name="Default",
    )


def require_supported_guardrail(ctx):
    if (
        ctx.obj.config.network_guardrail.enabled
        and ctx.obj.environment is not None
    ):
        raise click.ClickException(
            "Guardrail integration currently supports generated "
            "environments only."
        )


def require_no_guardrail_state(ctx):
    if ctx.obj.guardrail.state_path.exists():
        raise click.ClickException(
            "Guardrail recovery state exists. "
            "Run guardrail-restore before redeploying or compiling."
        )


def preflight_deployment(ctx):
    require_supported_guardrail(ctx)
    require_no_guardrail_state(ctx)

    if ctx.obj.config.network_guardrail.enabled:
        ctx.obj.guardrail.validate_policy()


@click.group()
@click.option(
    "--type",
    "environment_type",
    help="Environment class name, generated name, or JSON path",
    required=True,
    type=str,
)
@click.option(
    "--config-file",
    help="Path to the MHBench configuration JSON",
    default="config/config.json",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
)
@click.pass_context
def env(ctx, environment_type: str, config_file: str):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    experiment_dir = f"./output/misc/{timestamp}"
    os.makedirs(experiment_dir, exist_ok=True)

    ctx.ensure_object(SimpleNamespace)

    config = ConfigService(config_file).get_config()
    ctx.obj.config = config
    ctx.obj.config_path = config_file

    conn = create_openstack_connection(config.openstack_config)
    ctx.obj.guardrail = GuardrailLifecycle(conn, config)

    ansible_runner = AnsibleRunner(
        os.path.expanduser(config.openstack_config.ssh_key_path),
        None,
        "./ansible/",
        experiment_dir,
        False,
    )

    environment: TerraformDeployer | None = None
    topology: NetworkTopology | None = None
    orchestrator: EnvGenDeployer | None = None

    environment_class = getattr(
        env_module,
        environment_type,
        None,
    )

    if environment_class is not None:
        environment = environment_class(
            ansible_runner,
            conn,
            config.external_ip,
            config,
        )
        click.echo(
            f"Loaded specification-based environment: "
            f"{environment_type}"
        )
    else:
        if (
            environment_type.endswith(".json")
            or "/" in environment_type
        ):
            env_path = environment_type
        else:
            env_path = os.path.join(
                "src/environments/generated",
                environment_type + ".json",
            )

        try:
            with open(env_path, encoding="utf-8") as file:
                topology = NetworkTopology(**json.load(file))
        except FileNotFoundError as error:
            raise click.ClickException(
                f"Could not find environment: {env_path}"
            ) from error

        click.echo(f"Loaded generated environment: {env_path}")
        orchestrator = EnvGenDeployer(config, conn)

    ctx.obj.environment = environment
    ctx.obj.orchestrator = orchestrator
    ctx.obj.topology = topology


@env.command()
@click.option(
    "--skip_network",
    help="Skip network setup",
    is_flag=True,
)
@click.pass_context
def setup(ctx, skip_network: bool):
    require_supported_guardrail(ctx)
    click.echo("Setting up the environment...")

    if ctx.obj.environment is not None:
        if skip_network:
            ctx.obj.environment.find_management_server()
            ctx.obj.environment.parse_network()
        else:
            require_no_guardrail_state(ctx)
            ctx.obj.environment.deploy_topology()
            ctx.obj.environment.setup()

        ctx.obj.environment.runtime_setup()
        return

    if not skip_network:
        preflight_deployment(ctx)
        ctx.obj.orchestrator.deploy_environment(ctx.obj.topology)
        ctx.obj.guardrail.apply()

    # Refuse runtime startup if ON is not applied, rules differ,
    # or OFF still has recovery state from an earlier application.
    ctx.obj.guardrail.verify()
    ctx.obj.orchestrator.runtime_setup()

    click.echo("Runtime setup completed")


@env.command()
@click.option(
    "--skip_network",
    help="Skip network setup",
    is_flag=True,
)
@click.option(
    "--skip_host",
    help="Skip host setup",
    is_flag=True,
)
@click.pass_context
def compile(ctx, skip_network: bool, skip_host: bool):
    require_no_guardrail_state(ctx)

    if ctx.obj.config.network_guardrail.enabled:
        raise click.ClickException(
            "Set network_guardrail.enabled to false for compilation. "
            "Guardrail enforcement is applied during test deployment."
        )

    click.echo("Compiling the environment...")

    if ctx.obj.environment is not None:
        ctx.obj.environment.compile(
            not skip_network,
            not skip_host,
        )
    else:
        ctx.obj.orchestrator.compile_environment(ctx.obj.topology)


@env.command()
@click.pass_context
def teardown(ctx):
    click.echo("Restoring guardrail settings...")
    ctx.obj.guardrail.restore()

    click.echo("Tearing down the environment...")

    if ctx.obj.environment is not None:
        ctx.obj.environment.teardown()
    else:
        ctx.obj.orchestrator.cleaner.clean_environment()

    click.echo("Environment has been torn down")


@env.command()
@click.pass_context
def deploy_network(ctx):
    preflight_deployment(ctx)
    click.echo("Deploying environment...")

    if ctx.obj.environment is not None:
        ctx.obj.environment.deploy_topology()
    else:
        ctx.obj.orchestrator.deploy_environment(ctx.obj.topology)

        group_id = ctx.obj.guardrail.apply()

        if group_id is None:
            click.echo("Network guardrail OFF")
        else:
            click.echo(
                f"Network guardrail applied: {group_id}"
            )


@env.command("guardrail-apply")
@click.pass_context
def guardrail_apply(ctx):
    require_supported_guardrail(ctx)

    if not ctx.obj.config.network_guardrail.enabled:
        raise click.ClickException(
            "Set network_guardrail.enabled to true first."
        )

    group_id = ctx.obj.guardrail.apply()
    click.echo(f"Network guardrail applied: {group_id}")


@env.command("guardrail-verify")
@click.pass_context
def guardrail_verify(ctx):
    require_supported_guardrail(ctx)
    ctx.obj.guardrail.verify()

    if ctx.obj.config.network_guardrail.enabled:
        click.echo("Guardrail rules and attachment verified")
    else:
        click.echo("Guardrail OFF; no recovery state present")


@env.command("guardrail-restore")
@click.pass_context
def guardrail_restore(ctx):
    if ctx.obj.guardrail.restore():
        click.echo("Original security groups restored")
    else:
        click.echo("No guardrail recovery state found")


if __name__ == "__main__":
    env()