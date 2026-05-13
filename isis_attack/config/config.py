"""配置加载器：实现默认值 → YAML → CLI 三层优先级合并。"""
import os
from .types import (
    AttackConfig, IIHConfig, LSPConfig, DoSConfig, MITMConfig, ReplayConfig,
    AttackMode, SniffMode,
)

_CONFIG_CLASS_MAP = {
    "iih-inject":       IIHConfig,
    "adjacency-break":  IIHConfig,
    "dis-hijack":       IIHConfig,
    "route-inject":     LSPConfig,
    "max-seq":          LSPConfig,
    "purge-lsp":        LSPConfig,
    "fight-back":       LSPConfig,
    "overload-bit":     LSPConfig,
    "flood":            DoSConfig,
    "spf-recalc":       DoSConfig,
    "db-overflow":      DoSConfig,
    "mitm":             MITMConfig,
    "replay":           ReplayConfig,
}


def load_yaml_config(path: str) -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"YAML 文件内容必须是字典，实际: {type(data)}")
    return data


def merge_config(yaml_data: dict, cli_kwargs: dict) -> dict:
    merged = dict(yaml_data)
    for key, value in cli_kwargs.items():
        if value is not None and value != "" and value != []:
            merged[key] = value
    return merged


def build_config(attack_name: str, cli_kwargs: dict, config_path: str = "") -> AttackConfig:
    config_cls = _CONFIG_CLASS_MAP[attack_name]

    yaml_data = {}
    if config_path and os.path.exists(config_path):
        yaml_data = load_yaml_config(config_path)

    merged = merge_config(yaml_data, cli_kwargs)

    mode = AttackMode.PASSIVE
    if merged.get("mode") == "active":
        mode = AttackMode.ACTIVE

    sniff_mode = SniffMode.HUB
    if merged.get("sniff_mode") == "arp_spoof":
        sniff_mode = SniffMode.ARP_SPOOF

    field_names = set(config_cls.__dataclass_fields__.keys())
    filtered = {k: v for k, v in merged.items() if k in field_names}

    return config_cls(
        iface=merged.get("iface", "eth0"),
        target=merged.get("target", "01:80:C2:00:00:14"),
        mode=mode,
        sniff_mode=sniff_mode,
        **{k: v for k, v in filtered.items() if k not in ("iface", "target", "mode", "sniff_mode")},
    )


def get_available_attacks() -> list:
    return sorted(_CONFIG_CLASS_MAP.keys())
