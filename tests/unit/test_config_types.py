import pytest
from isis_attack.config.types import (
    AttackMode, SniffMode, AttackCategory,
    AttackResult, AttackConfig, IIHConfig, LSPConfig,
    DoSConfig, MITMConfig, ReplayConfig,
)

def test_attack_mode_enum():
    assert AttackMode.PASSIVE.value == "passive"
    assert AttackMode.ACTIVE.value == "active"

def test_sniff_mode_enum():
    assert SniffMode.HUB.value == "hub"
    assert SniffMode.ARP_SPOOF.value == "arp_spoof"

def test_attack_category_enum():
    assert AttackCategory.ADJACENCY.value == "adjacency"
    assert AttackCategory.LSP.value == "lsp"
    assert AttackCategory.DOS.value == "dos"
    assert AttackCategory.PROTOCOL.value == "protocol"

def test_attack_result():
    r = AttackResult(success=True, packets_sent=10, target_affected=True, details="ok")
    assert r.success
    assert r.packets_sent == 10
    assert r.target_affected
    assert r.details == "ok"
    assert r.evidence == {}

def test_attack_config_defaults():
    c = AttackConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.mode == AttackMode.PASSIVE
    assert c.sniff_mode == SniffMode.HUB
    assert c.sys_id == "1921.6800.1001"
    assert c.area_addr == "49.0001"
    assert c.level == 1
    assert c.sniff_duration == 30

def test_iih_config():
    c = IIHConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.hello_interval == 10
    assert c.hold_timer == 30
    assert c.priority == 64

def test_lsp_config():
    c = LSPConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.lsp_id == ""
    assert c.sequence == 0x00000001
    assert c.remaining_lifetime == 1200
    assert c.overload_bit is False

def test_dos_config():
    c = DoSConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.duration == 60
    assert c.thread_count == 1

def test_mitm_config():
    c = MITMConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.action == "modify"
    assert c.modify_rules == []

def test_replay_config():
    c = ReplayConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.replay_loop is False
