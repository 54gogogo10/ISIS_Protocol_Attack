import click
from isis_attack.config.types import (
    AttackConfig, IIHConfig, LSPConfig, DoSConfig, MITMConfig, ReplayConfig,
    AttackMode, SniffMode,
)
from isis_attack.config.config import build_config
from isis_attack.attacks.adjacency.iih_inject import IIHInjectAttack
from isis_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from isis_attack.attacks.adjacency.dis_hijack import DISHijackAttack
from isis_attack.attacks.lsp.route_inject import RouteInjectAttack
from isis_attack.attacks.lsp.max_seq import MaxSeqAttack
from isis_attack.attacks.lsp.purge_lsp import PurgeLSPAttack
from isis_attack.attacks.lsp.fight_back import FightBackAttack
from isis_attack.attacks.lsp.overload_bit import OverloadBitAttack
from isis_attack.attacks.dos.flood import FloodAttack
from isis_attack.attacks.dos.spf_recalc import SPFRecalcAttack
from isis_attack.attacks.dos.db_overflow import DBOverflowAttack
from isis_attack.attacks.protocol.mitm import MITMAttack
from isis_attack.attacks.protocol.replay import ReplayAttack
from isis_attack.cli.formatters import format_table, format_json

ATTACK_REGISTRY = {
    "iih-inject":       (IIHInjectAttack, IIHConfig),
    "adjacency-break":  (AdjacencyBreakAttack, IIHConfig),
    "dis-hijack":       (DISHijackAttack, IIHConfig),
    "route-inject":     (RouteInjectAttack, LSPConfig),
    "max-seq":          (MaxSeqAttack, LSPConfig),
    "purge-lsp":        (PurgeLSPAttack, LSPConfig),
    "fight-back":       (FightBackAttack, LSPConfig),
    "overload-bit":     (OverloadBitAttack, LSPConfig),
    "flood":            (FloodAttack, DoSConfig),
    "spf-recalc":       (SPFRecalcAttack, DoSConfig),
    "db-overflow":      (DBOverflowAttack, DoSConfig),
    "mitm":             (MITMAttack, MITMConfig),
    "replay":           (ReplayAttack, ReplayConfig),
}


def _common_options(f):
    options = [
        click.option("--iface", required=True, help="网卡接口"),
        click.option("--target", required=True, help="目标 MAC 地址"),
        click.option("--passive/--active", "mode_flag", default=None),
        click.option("--sniff-mode", type=click.Choice(["hub", "arp_spoof"]), default="hub"),
        click.option("--sys-id", default="1921.6800.1001", help="System ID"),
        click.option("--area-addr", default="49.0001", help="Area 地址"),
        click.option("--level", type=int, default=1, help="ISIS 级别 (1/2)"),
        click.option("--sniff-duration", type=int, default=30),
        click.option("--arp-target-a", default=""),
        click.option("--arp-target-b", default=""),
        click.option("--arp-interval", type=int, default=2),
        click.option("--packet-rate", type=int, default=10),
        click.option("--max-packets", type=int, default=0),
        click.option("--verbose/--no-verbose", default=False),
        click.option("--config", "config_file", default=""),
        click.option("--pcap-output", default=""),
        click.option("--output", type=click.Choice(["table", "json"]), default="table"),
    ]
    for opt in reversed(options):
        f = opt(f)
    f = click.command()(f)
    return f


def _run_attack(attack_cls, config_cls, **kwargs):
    output_fmt = kwargs.pop("output", "table")
    config_file = kwargs.pop("config_file", "")

    if kwargs.get("mode_flag") is True:
        kwargs["mode"] = "passive"
    elif kwargs.get("mode_flag") is False:
        kwargs["mode"] = "active"

    config = build_config(attack_cls.name, kwargs, config_file)
    attack = attack_cls(config)
    result = attack.run()

    if output_fmt == "json":
        click.echo(format_json(result))
    else:
        click.echo(format_table(result))

    if not result.success:
        raise SystemExit(1)


def register_commands(cli: click.Group):
    for name, (attack_cls, config_cls) in ATTACK_REGISTRY.items():
        def _make_cmd(a_cls, c_cls):
            @_common_options
            @click.pass_context
            def cmd(ctx, **kwargs):
                filtered = {k: v for k, v in kwargs.items()
                           if k in c_cls.__dataclass_fields__ or k in ("mode_flag", "sniff_mode", "output", "config_file")}
                _run_attack(a_cls, c_cls, **filtered)
            cmd.name = name
            return cmd
        cmd = _make_cmd(attack_cls, config_cls)
        cli.add_command(cmd)
