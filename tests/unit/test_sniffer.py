import pytest
from isis_attack.core.sniffer import TopologyModel, LSPEntry, Sniffer, HAS_PCAP

def test_topology_model():
    t = TopologyModel()
    t.add_sys("1921.6800.1001", "49.0001")
    t.add_sys("1921.6800.1002", "49.0001")
    assert len(t.sys_ids) == 2
    assert len(t.area_addrs) == 1

def test_lsp_entry():
    e = LSPEntry(lsp_id="1921.6800.1001.00-00", sequence=5, remaining_lifetime=1100)
    assert e.sequence == 5
    assert e.remaining_lifetime == 1100

def test_sniffer_disabled_without_pcap():
    if HAS_PCAP:
        pytest.skip("pcap available, skipping none-available test")
    s = Sniffer(iface="eth0")
    assert s.available is False
    s.start(timeout=1)
    assert s.packets == []
