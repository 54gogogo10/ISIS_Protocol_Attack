"""ISIS PDU construction and parsing (TLV-encoded, L2 transport)."""
import struct
from functools import lru_cache
from scapy.all import Ether
from scapy.contrib.isis import (
    ISIS_CommonHdr,
    ISIS_L1_LAN_Hello,
    ISIS_L2_LAN_Hello,
    ISIS_P2P_Hello,
    ISIS_L1_LSP,
    ISIS_L2_LSP,
    ISIS_L1_CSNP,
    ISIS_L2_CSNP,
    ISIS_L1_PSNP,
    ISIS_L2_PSNP,
)

from .auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5, build_auth_tlv

# Pre-built constant bytes (avoids per-call allocations)
_TLV_PROTOCOLS = b"\x81\x01\xcc"   # TLV type=129, len=1, NLPID=0xCC (IPv4)
_LLC_BYTES = b"\xFE\xFE\x03"       # DSAP=0xFE, SSAP=0xFE, Ctrl=0x03

# PDU types
ISIS_TYPE_L1_IIH = 15
ISIS_TYPE_L2_IIH = 16
ISIS_TYPE_P2P_IIH = 17
ISIS_TYPE_L1_LSP = 18
ISIS_TYPE_L2_LSP = 20
ISIS_TYPE_L1_CSNP = 24
ISIS_TYPE_L2_CSNP = 25
ISIS_TYPE_L1_PSNP = 26
ISIS_TYPE_L2_PSNP = 27

ISIS_TYPE_NAMES = {
    15: "L1 IIH", 16: "L2 IIH", 17: "P2P IIH",
    18: "L1 LSP", 20: "L2 LSP",
    24: "L1 CSNP", 25: "L2 CSNP",
    26: "L1 PSNP", 27: "L2 PSNP",
}

# MAC addresses
ISIS_MAC_L1 = "01:80:C2:00:00:14"
ISIS_MAC_L2 = "01:80:C2:00:00:15"

# TLV types
TLV_AREA_ADDR = 1
TLV_IS_NEIGHBORS = 6
TLV_AUTH = 10
TLV_IP_INT_REACH = 128
TLV_PROTOCOLS = 129
TLV_IP_EXT_REACH = 130
TLV_IP_IFACE_ADDR = 132
TLV_AUTH_CRYPTO = 133
TLV_HOSTNAME = 137


def _sys_id_bytes(sys_id: str) -> bytes:
    """Convert '1921.6800.1001' to 6 bytes."""
    parts = sys_id.replace(".", "")
    if len(parts) != 12:
        raise ValueError(f"Invalid System ID: {sys_id}")
    return bytes.fromhex(parts)


def _mac_bytes(mac: str) -> bytes:
    """Convert '00:11:22:33:44:55' to 6 bytes."""
    return bytes(int(b, 16) for b in mac.split(":"))


def _build_level_mac(level: int) -> str:
    return ISIS_MAC_L1 if level == 1 else ISIS_MAC_L2


def _build_llc():
    return _LLC_BYTES


def build_isis_hdr(pdu_type: int, sys_id: str = "0000.0000.0000",
                   max_area: int = 3) -> bytes:
    """Build ISIS common header bytes."""
    sid = _sys_id_bytes(sys_id) if sys_id != "0000.0000.0000" else b"\x00" * 6
    id_len = len(sid)
    hdr_len = 8 + id_len
    hdr = struct.pack("!BBBBBBBB", 0x83, hdr_len, 1, id_len, pdu_type, 1, 0, max_area)
    hdr += sid
    return hdr


@lru_cache(maxsize=16)
def _build_area_tlv(area_addr: str) -> bytes:
    """Build Area Addresses TLV (type 1) — cached."""
    addr_parts = area_addr.replace(".", "")
    addr = bytes.fromhex(addr_parts) if len(addr_parts) % 2 == 0 else bytes.fromhex(addr_parts + "0")
    addr_len = len(addr)
    return struct.pack("!BB", TLV_AREA_ADDR, 1 + addr_len) + bytes([addr_len]) + addr


def _build_protocols_tlv() -> bytes:
    return _TLV_PROTOCOLS


def _build_ip_iface_tlv(ip_addr: str) -> bytes:
    """Build IP Interface Address TLV (type 132)."""
    parts = [int(x) for x in ip_addr.split(".")]
    return bytes([TLV_IP_IFACE_ADDR, 4]) + bytes(parts)


def build_ip_reachability_tlv(
    internal: bool = True,
    network_addr: str = "10.0.0.0",
    network_mask: str = "255.255.255.0",
    metric: int = 10,
) -> bytes:
    """Build an IP Reachability TLV (type 128 internal, 130 external)."""
    ip_parts = [int(x) for x in network_addr.split(".")]
    mask_parts = [int(x) for x in network_mask.split(".")]

    default_metric = metric & 0x3F
    if not internal:
        default_metric |= 0xC0  # external, type 7|6=11

    tlv_type = TLV_IP_INT_REACH if internal else TLV_IP_EXT_REACH
    entry = struct.pack("!B", default_metric)
    entry += b"\x80\x80\x80"  # delay/expense/error: S=1, value=0
    entry += bytes(ip_parts)
    entry += bytes(mask_parts)

    return struct.pack("!BB", tlv_type, len(entry)) + entry


def _build_is_neighbors_tlv(sys_ids: list) -> bytes:
    """Build IS Neighbors TLV (type 6). Each neighbor = 6B MAC."""
    value = b"".join(_mac_bytes(sid) for sid in sys_ids)
    return struct.pack("!BB", TLV_IS_NEIGHBORS, len(value)) + value


@lru_cache(maxsize=32)
def _build_hostname_tlv(hostname: str) -> bytes:
    """Build Hostname TLV (type 137) — cached."""
    name_bytes = hostname.encode("ascii")
    return struct.pack("!BB", TLV_HOSTNAME, len(name_bytes)) + name_bytes


def _resolve_hello_cls(level: int):
    """Return the correct Scapy Hello class for the given level."""
    if level == 1:
        return ISIS_L1_LAN_Hello
    elif level == 2:
        return ISIS_L2_LAN_Hello
    else:
        raise ValueError(f"Invalid ISIS level: {level}")


def _resolve_hdr_cls(level: int, pdu_type_base: int):
    """Return (common_hdr, pdu_type) for the given level and base type."""
    if level == 1:
        return ISIS_CommonHdr(pdutype=pdu_type_base)
    elif level == 2:
        # L2 uses pdutype = base + 1 for some PDU types
        return ISIS_CommonHdr(pdutype=pdu_type_base + 1)
    else:
        raise ValueError(f"Invalid ISIS level: {level}")


def build_iih_packet(
    sys_id: str,
    area_addr: str,
    src_mac: str,
    level: int = 1,
    priority: int = 64,
    hold_timer: int = 30,
    hello_interval: int = 10,
    circ_id: int = 0,
    auth_type: int = AUTH_NONE,
    auth_key: bytes = b"",
    neighbors: list | None = None,
):
    """Build a complete ISIS IIH (Hello) PDU. Returns L2 packet (bytes-like)."""
    dst_mac = _build_level_mac(level)
    pdu_type = ISIS_TYPE_L1_IIH if level == 1 else ISIS_TYPE_L2_IIH
    hello_cls = _resolve_hello_cls(level)

    hello = hello_cls(
        circuittype=level,
        sourceid=sys_id,
        holdingtime=hold_timer,
        pdulength=1492,
        priority=priority,
        lanid=sys_id + ".00",
    )

    pkt = Ether(dst=dst_mac, src=src_mac) / _build_llc() / ISIS_CommonHdr(pdutype=pdu_type) / hello
    raw_pkt = bytes(pkt)

    # Append TLVs as raw bytes
    tlvs = b""
    tlvs += _build_area_tlv(area_addr)
    tlvs += _build_protocols_tlv()
    if neighbors:
        tlvs += _build_is_neighbors_tlv(neighbors)
    if auth_key and auth_type != AUTH_NONE:
        tlvs += build_auth_tlv(auth_type, auth_key, raw_pkt + tlvs)

    return raw_pkt + tlvs


def _compute_lsp_checksum(lsp_body: bytes) -> int:
    """Compute ISIS LSP 16-bit checksum — zero-allocation via memoryview.

    Covers from Source ID (after lifetime) to end of LSP.
    Checksum field at offset 12 into source-id area is zeroed.
    """
    ba = bytearray(lsp_body[2:])
    ba[12:14] = b"\x00\x00"
    if len(ba) % 2:
        ba.append(0)
    return sum(memoryview(ba).cast("H")) & 0xFFFF


def _build_lsp_raw(
    sys_id: str,
    lsp_id: str,
    level: int = 1,
    sequence: int = 0x00000001,
    remaining_lifetime: int = 1200,
    overload_bit: bool = False,
    tlvs: bytes = b"",
) -> bytes:
    pdu_type = ISIS_TYPE_L1_LSP if level == 1 else ISIS_TYPE_L2_LSP

    clean = lsp_id.replace(".", "").replace("-", "")
    if len(clean) < 14:
        raise ValueError(
            f"LSP ID too short: '{lsp_id}' — expected format like "
            f"'CCCC.CCCC.CCCC.00-00' (16 hex chars + separators)"
        )
    if len(clean) < 16:
        clean = clean.ljust(16, "0")
    lsp_id_bytes = bytes.fromhex(clean[:16])

    # Flags / typeblock: bits [7-6]=L1L2, bit[5]=overload, bit[4]=attached
    typeblock = 0x03
    if overload_bit:
        typeblock |= 0x20  # Set OL bit

    lsp_body = (
        struct.pack("!H", remaining_lifetime)
        + lsp_id_bytes
        + struct.pack("!I", sequence)
        + struct.pack("!H", 0)
        + struct.pack("!B", typeblock)
        + tlvs
    )

    # Compute and patch checksum
    chk = _compute_lsp_checksum(lsp_body)
    lsp_body = lsp_body[:14] + struct.pack("!H", chk) + lsp_body[16:]

    # ISIS common header
    sid = _sys_id_bytes(sys_id) if sys_id != "0000.0000.0000" else b"\x00" * 6
    id_len = len(sid)
    hdr_len = 8 + id_len
    isis_hdr = struct.pack(
        "!BBBBBBBB", 0x83, hdr_len, 1, id_len, pdu_type, 1, 0, 3
    ) + sid

    return isis_hdr + lsp_body


def build_lsp_packet(
    sys_id: str,
    lsp_id: str,
    src_mac: str,
    level: int = 1,
    sequence: int = 0x00000001,
    remaining_lifetime: int = 1200,
    overload_bit: bool = False,
    tlvs: bytes = b"",
):
    dst_mac = _build_level_mac(level)
    dst_bytes = _mac_bytes(dst_mac)
    src_bytes = _mac_bytes(src_mac)

    isis_pdu = _build_lsp_raw(
        sys_id=sys_id, lsp_id=lsp_id, level=level,
        sequence=sequence, remaining_lifetime=remaining_lifetime,
        overload_bit=overload_bit, tlvs=tlvs,
    )

    # 802.3 LLC encapsulation
    payload = struct.pack("!BBB", 0xFE, 0xFE, 0x03) + isis_pdu
    eth = dst_bytes + src_bytes + struct.pack("!H", len(payload)) + payload

    return eth


def build_lsp_with_tlvs(
    sys_id: str,
    lsp_id: str,
    src_mac: str,
    level: int = 1,
    sequence: int = 0x00000001,
    remaining_lifetime: int = 1200,
    overload_bit: bool = False,
    metric: int = 10,
    network_addr: str = "10.0.0.0",
    network_mask: str = "255.255.255.0",
    area_addr: str = "49.0001",
):
    """Build a complete LSP with IP reachability TLVs.

    High-level builder used by attack modules. Includes Area Addresses
    TLV (type 1) for FRR acceptance. Note: authentication TLV is NOT
    appended — callers needing auth must append build_auth_tlv() manually.
    """
    tlvs = b""
    tlvs += _build_area_tlv(area_addr)
    tlvs += _build_protocols_tlv()
    tlvs += _build_hostname_tlv(sys_id.replace(".", "-"))

    if network_addr != "0.0.0.0":
        tlvs += build_ip_reachability_tlv(
            internal=True, network_addr=network_addr,
            network_mask=network_mask, metric=metric,
        )

    return build_lsp_packet(
        sys_id=sys_id, lsp_id=lsp_id, src_mac=src_mac,
        level=level, sequence=sequence,
        remaining_lifetime=remaining_lifetime,
        overload_bit=overload_bit, tlvs=tlvs,
    )


def parse_isis_packet(data: bytes):
    """Parse raw bytes into a Scapy ISIS packet."""
    try:
        pkt = Ether(data)
        if pkt.haslayer(ISIS_CommonHdr):
            return pkt
        return None
    except Exception:
        return None


def get_isis_type_name(ptype: int) -> str:
    return ISIS_TYPE_NAMES.get(ptype, f"Unknown({ptype})")
