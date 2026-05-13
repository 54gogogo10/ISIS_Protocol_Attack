"""Tests for CLI layer — command registration, help output, version."""
import click
from click.testing import CliRunner
from isis_attack.cli.main import cli
from isis_attack.cli.commands import ATTACK_REGISTRY


def test_cli_help():
    """isi-attack --help should list all 13 subcommands."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for name in ATTACK_REGISTRY:
        assert name in result.output


def test_cli_version():
    """isi-attack --version should show version."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_attack_registry_has_13_attacks():
    """ATTACK_REGISTRY should contain exactly 13 entries."""
    assert len(ATTACK_REGISTRY) == 13


def test_attack_registry_keys_match_class_names():
    """Each ATTACK_REGISTRY key should match the attack class name attribute."""
    for key, (attack_cls, _) in ATTACK_REGISTRY.items():
        assert attack_cls.name == key, f"{key} != {attack_cls.name}"


def test_attack_registry_keys_match_config_map():
    """Each ATTACK_REGISTRY key should exist in build_config's _CONFIG_CLASS_MAP."""
    from isis_attack.config.config import _CONFIG_CLASS_MAP as config_map
    for key in ATTACK_REGISTRY:
        assert key in config_map, f"{key} missing from config map"


def test_each_command_registered():
    """Each attack in ATTACK_REGISTRY should be a subcommand of the CLI group."""
    for name in ATTACK_REGISTRY:
        cmd = cli.get_command(None, name)
        assert cmd is not None, f"Command {name} not registered"
        assert isinstance(cmd, click.Command)


def test_each_command_accepts_iface_target():
    """Each subcommand should accept --iface and --target options."""
    for name in ATTACK_REGISTRY:
        cmd = cli.get_command(None, name)
        params = {p.name for p in cmd.params}
        assert "iface" in params, f"{name} missing --iface"
        assert "target" in params, f"{name} missing --target"
