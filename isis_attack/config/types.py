from dataclasses import dataclass, field
from enum import Enum


class AttackMode(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class SniffMode(Enum):
    HUB = "hub"
    ARP_SPOOF = "arp_spoof"


class AttackCategory(Enum):
    ADJACENCY = "adjacency"
    LSP = "lsp"
    DOS = "dos"
    PROTOCOL = "protocol"


@dataclass
class AttackResult:
    success: bool
    packets_sent: int
    target_affected: bool
    details: str
    evidence: dict = field(default_factory=dict)


@dataclass
class AttackConfig:
    """所有攻击类型共享的基础配置"""
    iface: str
    target: str
    mode: AttackMode = AttackMode.PASSIVE
    sniff_mode: SniffMode = SniffMode.HUB
    sys_id: str = "1921.6800.1001"
    area_addr: str = "49.0001"
    level: int = 1

    sniff_duration: int = 30

    arp_target_a: str = ""
    arp_target_b: str = ""
    arp_interval: int = 2

    packet_rate: int = 10
    max_packets: int = 0

    verbose: bool = False


@dataclass
class IIHConfig(AttackConfig):
    """IIH 注入 / 邻接破坏 / DIS 操纵 专用配置"""
    hello_interval: int = 10
    hold_timer: int = 30
    priority: int = 64
    auth_type: str = "none"
    auth_key: str = ""
    circ_id: int = 0


@dataclass
class LSPConfig(AttackConfig):
    """LSP 攻击专用配置"""
    lsp_id: str = ""
    sequence: int = 0x00000001
    remaining_lifetime: int = 1200
    overload_bit: bool = False
    metric: int = 10
    network_addr: str = "10.0.0.0"
    network_mask: str = "255.255.255.0"
    auth_type: str = "none"
    auth_key: str = ""


@dataclass
class DoSConfig(AttackConfig):
    """拒绝服务攻击专用配置"""
    duration: int = 60
    thread_count: int = 1
    lsp_change_interval: int = 2
    lsp_count: int = 1000


@dataclass
class MITMConfig(AttackConfig):
    """中间人攻击专用配置"""
    target_a: str = ""
    target_b: str = ""
    action: str = "modify"
    modify_rules: list = field(default_factory=list)


@dataclass
class ReplayConfig(AttackConfig):
    """重放攻击专用配置"""
    capture_file: str = ""
    replay_loop: bool = False
    replay_interval: int = 0
    modify_fields: list = field(default_factory=list)
