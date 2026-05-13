import pytest
from isis_attack.core.packet import (
    ISIS_TYPE_L1_IIH, ISIS_TYPE_L2_IIH, ISIS_TYPE_L1_LSP, ISIS_TYPE_L2_LSP,
    ISIS_MAC_L1, ISIS_MAC_L2,
    build_iih_packet, build_lsp_packet, build_lsp_with_tlvs,
    build_ip_reachability_tlv,
    build_isis_hdr, parse_isis_packet,
    TLV_AREA_ADDR, TLV_IP_INT_REACH, TLV_IP_EXT_REACH, TLV_PROTOCOLS,
)

def test_constants():
    assert ISIS_TYPE_L1_IIH == 15
    assert ISIS_TYPE_L2_IIH == 16
    assert ISIS_TYPE_L1_LSP == 18
    assert ISIS_TYPE_L2_LSP == 20

def test_mac_addresses():
    assert ISIS_MAC_L1 == "01:80:C2:00:00:14"
    assert ISIS_MAC_L2 == "01:80:C2:00:00:15"

def test_build_iih_l1():
    pkt = build_iih_packet(
        sys_id="1921.6800.1001",
        area_addr="49.0001",
        src_mac="00:11:22:33:44:55",
        level=1,
        priority=64,
        hold_timer=30,
    )
    assert pkt is not None
    from scapy.layers.l2 import Ether, LLC
    pkt_obj = Ether(pkt)
    assert pkt_obj.dst == ISIS_MAC_L1.lower()

def test_build_lsp_packet():
    pkt = build_lsp_packet(
        sys_id="1921.6800.1001",
        lsp_id="1921.6800.1001.00-00",
        src_mac="00:11:22:33:44:55",
        level=1,
        sequence=0x00000001,
        remaining_lifetime=1200,
        tlvs=b"",
    )
    assert pkt is not None
    assert pkt[0:6] == bytes.fromhex("0180C2000014")  # dst MAC

def test_build_ip_reachability_tlv():
    tlv = build_ip_reachability_tlv(
        internal=True,
        network_addr="10.0.0.0",
        network_mask="255.255.255.0",
        metric=10,
    )
    assert tlv[0] == TLV_IP_INT_REACH
    assert len(tlv) == 14  # type(1) + len(1) + 12B entry

def test_build_isis_hdr():
    hdr = build_isis_hdr(pdu_type=ISIS_TYPE_L1_IIH, sys_id="1921.6800.1001")
    assert hdr[0] == 0x83
    assert hdr[4] == ISIS_TYPE_L1_IIH

def test_build_lsp_with_tlvs():
    pkt = build_lsp_with_tlvs(
        sys_id="1921.6800.1001",
        lsp_id="1921.6800.1001.00-00",
        src_mac="00:11:22:33:44:55",
        level=1,
        metric=20,
        network_addr="10.99.0.0",
        overload_bit=True,
    )
    assert pkt is not None
